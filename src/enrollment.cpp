#include "control/service.hpp"
#include <regex>

namespace control {
namespace {
// Node endpoint syntax is deliberately restricted: DNS names need an independent resolver/prober before
// scheduling.
void validate_announcement(const Json &body, bool allow_loopback) {
    require(integer(body, "protocol", 1, 1) == 1, "incompatible", "Unsupported protocol");
    auto endpoint = text(body, "endpoint", 256);
    static const std::regex syntax(R"(^[a-zA-Z0-9.\[\]:-]+:[0-9]{1,5}$)");
    require(std::regex_match(endpoint, syntax), "invalid", "Expected host:port endpoint");
    require(allow_loopback || (!endpoint.starts_with("127.") && !endpoint.starts_with("localhost:") &&
                               !endpoint.starts_with("[::1]:")),
            "invalid", "Loopback node endpoint disabled");
    (void)text(body, "region", 64);
    (void)text(body, "operator", 64);
    (void)integer(body, "slots", 1, 100000);
    (void)integer(body, "bandwidth", 1, 1000000000000LL);
}
} // namespace
Json Service::enrollment(Database &db, const std::string &path, const Json &body) {
    bool node_identity = path.starts_with("/v1/enrollment/");
    auto prefix = node_identity ? "/v1/enrollment/" : "/v1/identity/";
    auto kind = node_identity ? "node" : "player";
    if (path == std::string(prefix) + "challenge") {
        auto public_key = body.contains("certificate") ? std::string() : text(body, "public_key", 64);
        std::string legacy_id;
        if (!node_identity && body.contains("certificate") && !body.contains("device_grant")) {
            auto legacy = legacy_identity(body["certificate"], text(body, "issuer_signature", 1024));
            legacy_id = legacy.first;
            public_key = legacy.second;
        } else if (!body.contains("device_grant"))
            require(unhex(public_key).size() == 32, "invalid", "Expected Ed25519 public key");
        std::string credential_id;
        Json payload = body;
        payload.erase("identity_public_key");
        // A browser-approved launcher proves the delegated device key, never uploads the user key.
        if (!node_identity && body.contains("device_grant")) {
            auto proof = verify_delegation(body);
            legacy_id = proof.account;
            public_key = proof.key;
            payload["identity_public_key"] = proof.public_key;
            payload["delegation_digest"] = proof.digest;
            auto allowed = db.query("SELECT 1 FROM devices WHERE account_id=$1 AND id=$2 AND "
                                    "delegation_digest=$3 AND NOT revoked AND valid_until>clock_timestamp()",
                                    {proof.account, proof.device, proof.digest});
            require(allowed.size() == 1, "revoked", "Control device authorization required", 401);
        }
        require(!node_identity || !body.contains("device_grant"), "invalid",
                "Node cannot use a player delegation");
        if (node_identity) {
            if (body.contains("node_id")) {
                auto known = db.query("SELECT public_key FROM nodes WHERE id=$1 AND status<>'revoked'",
                                      {text(body, "node_id", 80)});
                require(known.size() && secure_equal(known.at(0, 0), public_key), "unauthorized",
                        "Unknown node identity", 401);
            } else {
                auto credential = text(body, "credential", 512);
                auto row = db.query("SELECT id FROM enrollment_credentials WHERE digest=$1 AND enabled",
                                    {sha256(credential)});
                require(row.size() == 1, "unauthorized", "Invalid enrollment credential", 401);
                credential_id = row.at(0, 0);
            }
            validate_announcement(body, config_.allow_loopback_nodes);
            require(integer(body, "slots", 1, 100000) <= config_.node_slot_limit &&
                        integer(body, "bandwidth", 1, 1000000000000LL) <= config_.node_bandwidth_limit,
                    "capacity", "Announcement exceeds server node budget", 409);
            payload.erase("credential");
        } else
            (void)text(body, "device_id", 64);
        if (!legacy_id.empty())
            payload["verified_account_id"] = legacy_id;
        // Never accept an externally supplied derived identity, including in Ed25519 test identities.
        if (legacy_id.empty())
            payload.erase("verified_account_id");
        idempotency_lock(db, "challenge", public_key);
        // Cap outstanding challenges per public key, in addition to the public transport budget.
        auto count =
            db.query("SELECT count(*) FROM challenges WHERE public_key=$1 AND expires_at>clock_timestamp()",
                     {public_key});
        require(count.number(0) < 8, "rate_limited", "Too many pending challenges", 429);
        auto id = random_id();
        auto message = Json({{"aud", config_.audience},
                             {"kind", kind},
                             {"challenge_id", id},
                             {"nonce", random_id()},
                             {"public_key", public_key},
                             {"request_digest", sha256(payload.dump())}})
                           .dump();
        db.query(R"SQL(INSERT INTO challenges(id,kind,public_key,credential_id,payload,message,expires_at)
           VALUES($1,$2,$3,NULLIF($4,''),$5::jsonb,$6,clock_timestamp()+interval '60 seconds'))SQL",
                 {id, kind, public_key, credential_id, payload.dump(), message});
        return {{"challenge_id", id}, {"message", message}, {"expires_in", 60}};
    }
    if (path == std::string(prefix) + "prove") {
        auto id = text(body, "challenge_id", 64);
        auto row = db.query(R"SQL(SELECT public_key,payload,message,credential_id,used,
           expires_at>clock_timestamp(),result_epoch FROM challenges WHERE id=$1 AND kind=$2 FOR UPDATE)SQL",
                            {id, kind});
        require(row.size() == 1 && row.at(0, 5) == "t", "expired", "Challenge expired", 401);
        require(verify_account_proof(row.at(0, 0), row.at(0, 2), text(body, "signature", 256)),
                "unauthorized", "Invalid possession proof", 401);
        auto payload = row.json(0, 1);
        auto public_key = row.at(0, 0);
        auto identity = payload.value("verified_account_id",
                                      std::string(node_identity ? "n_" : "u_") + sha256(public_key));
        idempotency_lock(db, identity, "identity");
        if (node_identity) {
            auto existing =
                db.query("SELECT epoch,status,pool FROM nodes WHERE id=$1 FOR UPDATE", {identity});
            require(existing.size() == 0 || existing.at(0, 1) != "revoked", "revoked", "Node revoked", 403);
            if (row.at(0, 4) == "t") {
                require(existing.size() && existing.at(0, 0) == row.at(0, 6), "stale", "Proof superseded",
                        409);
                return grant({"node", identity, "", row.at(0, 6)});
            }
            if (row.at(0, 3).empty()) {
                require(existing.size(), "unauthorized", "Existing identity required", 401);
                auto epoch = random_id();
                db.query("UPDATE nodes SET epoch=$2,sequence=0 WHERE id=$1", {identity, epoch});
                db.query("UPDATE challenges SET used=true,result_epoch=$2 WHERE id=$1", {id, epoch});
                return grant({"node", identity, "", epoch});
            }
            auto credential =
                db.query("SELECT pool,quota FROM enrollment_credentials WHERE id=$1 AND enabled FOR UPDATE",
                         {row.at(0, 3)});
            require(credential.size() == 1, "revoked", "Enrollment credential revoked", 401);
            if (existing.size() == 0 && !credential.at(0, 1).empty()) {
                auto used = db.query("SELECT count(*) FROM nodes WHERE credential_id=$1", {row.at(0, 3)});
                require(used.number(0) < credential.number(0, 1), "capacity", "Enrollment pool quota reached",
                        409);
            }
            auto epoch = random_id();
            db.query(
                R"SQL(INSERT INTO nodes(id,public_key,credential_id,pool,region,operator,endpoint,epoch,slots,bandwidth,shard)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::integer,$10::bigint,$11::integer)
               ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch,region=excluded.region,operator=excluded.operator,
               endpoint=excluded.endpoint,slots=excluded.slots,bandwidth=excluded.bandwidth,
               status=CASE WHEN nodes.status='draining' THEN 'draining' ELSE 'probing' END,
               sequence=CASE WHEN nodes.epoch=excluded.epoch THEN nodes.sequence ELSE 0 END,version=nodes.version+1)SQL",
                {identity, public_key, row.at(0, 3), credential.at(0, 0), text(payload, "region", 64),
                 text(payload, "operator", 64), text(payload, "endpoint", 256), epoch,
                 std::to_string(integer(payload, "slots", 1, 100000)),
                 std::to_string(integer(payload, "bandwidth", 1, 1000000000000LL)),
                 std::to_string(std::stoul(sha256(public_key).substr(0, 4), nullptr, 16) % 64)});
            db.query("UPDATE challenges SET used=true,result_epoch=$2 WHERE id=$1", {id, epoch});
            auto result = grant({"node", identity, "", epoch});
            result["pool"] = credential.at(0, 0);
            result["status"] = "probing";
            return result;
        }
        db.query("INSERT INTO identities(id,public_key,username) VALUES($1,$2,NULLIF($3,'')) ON CONFLICT(id) "
                 "DO NOTHING",
                 {identity, payload.value("identity_public_key", public_key),
                  payload.contains("certificate") ? text(payload["certificate"], "username", 32) : ""});
        auto stored = db.query("SELECT public_key FROM identities WHERE id=$1", {identity});
        require(stored.size() &&
                    secure_equal(stored.at(0, 0), payload.value("identity_public_key", public_key)),
                "conflict", "Identity key cannot change", 409);
        auto device = text(payload, "device_id", 64);
        auto device_row = db.query("SELECT epoch,revoked,delegation_digest,"
                                   "COALESCE(extract(epoch FROM valid_until)::bigint,9223372036854775807) "
                                   "FROM devices WHERE account_id=$1 AND id=$2",
                                   {identity, device});
        require(!device_row.size() || device_row.at(0, 1) != "t", "revoked", "Device revoked", 403);
        int64_t expires = INT64_MAX;
        if (payload.contains("device_grant")) {
            require(device_row.size() &&
                        device_row.at(0, 2) == payload.at("delegation_digest").get<std::string>() &&
                        device_row.number(0, 3) > unix_seconds(),
                    "revoked", "Device authorization expired", 401);
            expires = device_row.number(0, 3);
        }
        auto count = db.query("SELECT count(*) FROM devices WHERE account_id=$1 AND NOT revoked", {identity});
        require(device_row.size() || count.number(0) < 16, "capacity", "Device limit reached", 409);
        if (row.at(0, 4) == "t") {
            require(device_row.size() && device_row.at(0, 0) == row.at(0, 6), "stale", "Proof superseded",
                    409);
            return grant({"player", identity, device, row.at(0, 6), expires});
        }
        auto epoch =
            payload.contains("device_grant") && device_row.size() ? device_row.at(0, 0) : random_id();
        db.query(R"SQL(INSERT INTO devices(account_id,id,epoch) VALUES($1,$2,$3)
            ON CONFLICT(account_id,id) DO UPDATE SET epoch=excluded.epoch)SQL",
                 {identity, device, epoch});
        db.query("UPDATE challenges SET used=true,result_epoch=$2 WHERE id=$1", {id, epoch});
        return grant({"player", identity, device, epoch, expires});
    }
    throw Error(404, "not_found", "Unknown enrollment operation");
}
Json Service::node(Database &db, const std::string &path, const Json &body, const Actor &actor) {
    actor_kind(actor, "node");
    if (path == "/v1/node/activate") {
        auto proof_endpoint = text(body, "proof_endpoint", 256);
        auto row = db.query("SELECT endpoint,public_key,status FROM nodes WHERE id=$1", {actor.id});
        require(row.size() && row.at(0, 2) == "probing", "conflict", "Node is not awaiting verification",
                409);
        require(probe_node(row.at(0, 0), proof_endpoint, row.at(0, 1), config_.allow_loopback_nodes),
                "unreachable", "Node endpoint verification failed", 409);
        db.query("UPDATE nodes SET status='active',version=version+1 WHERE id=$1", {actor.id});
        return {{"id", actor.id}, {"status", "active"}};
    }
    if (path == "/v1/node/heartbeat") {
        auto sequence = integer(body, "sequence", 1, INT64_MAX);
        auto slots = integer(body, "observed_slots", 0, 1000000);
        auto bandwidth = integer(body, "observed_bandwidth", 0, 1000000000000LL);
        auto row =
            db.query(R"SQL(UPDATE nodes SET sequence=$2::bigint,observed_slots=$3::integer,
            observed_bandwidth=$4::bigint,heartbeat=$5::jsonb,
            health_until=clock_timestamp()+$6::integer*interval '1 second'
            WHERE id=$1 AND sequence<$2::bigint RETURNING status,version)SQL",
                     {actor.id, std::to_string(sequence), std::to_string(slots), std::to_string(bandwidth),
                      body.dump(), std::to_string(config_.node_lease_seconds)});
        require(row.size() == 1, "stale", "Stale node heartbeat", 409);
        return {{"status", row.at(0, 0)},
                {"version", row.number(0, 1)},
                {"lease_seconds", config_.node_lease_seconds}};
    }
    if (path == "/v1/node/renew")
        return grant(actor);
    throw Error(404, "not_found", "Unknown node operation");
}
} // namespace control
