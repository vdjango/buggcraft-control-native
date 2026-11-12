#include "control/service.hpp"
#include <algorithm>
#include <openssl/crypto.h>

namespace control {
Service::Service(Config config) : config_(std::move(config)), signer_(config_.signing_key) {
    auto token = read_secret(config_.admin_token_file, 4096);
    while (!token.empty() && (token.back() == '\n' || token.back() == '\r'))
        token.pop_back();
    require(token.size() >= 32, "config", "Administrator token must be at least 32 bytes", 500);
    admin_digest_ = sha256(token);
    if (config_.browser) {
        browser_signer_ = std::make_unique<Signer>(config_.browser->issuer_key);
        require(ssh_public_key(browser_signer_->public_key()) == config_.browser->issuer_public, "config",
                "Browser issuer public/private keys do not match", 500);
        browser_audience_ = read_secret(config_.browser->audience_key_file, 4096);
        while (!browser_audience_.empty() &&
               (browser_audience_.back() == '\n' || browser_audience_.back() == '\r'))
            browser_audience_.pop_back();
        require(browser_audience_.size() >= 32, "config", "Browser audience key is too short", 500);
        browser_smtp_ = config_.browser->smtp_file.empty()
                            ? Json({{"required", true}})
                            : parse_json(read_secret(config_.browser->smtp_file, 16384));
        require(browser_smtp_.is_object(), "config", "Invalid SMTP settings", 500);
    }
}
void Service::actor_kind(const Actor &actor, std::string_view kind) const {
    require(actor.kind == kind, "forbidden", "Authorization scope does not permit this operation", 403);
}
void Service::idempotency_lock(Database &db, std::string_view actor, std::string_view key) const {
    db.lock(std::string(actor) + ":" + std::string(key));
}
Json Service::grant(const Actor &actor) const {
    auto expires = std::min(unix_seconds() + config_.grant_seconds, actor.expires);
    return {{"token", signer_.token({{"v", 1},
                                     {"aud", config_.audience},
                                     {"kind", actor.kind},
                                     {"sub", actor.id},
                                     {"device", actor.device},
                                     {"epoch", actor.epoch},
                                     {"exp", expires}})},
            {"expires_at", expires},
            {"id", actor.id},
            {"epoch", actor.epoch},
            {"signing_public_key", signer_.public_key()}};
}
Actor Service::authenticate(Database &db, std::string_view token) {
    auto claims = signer_.verify(token, config_.audience);
    Actor actor{text(claims, "kind"), text(claims, "sub"), claims.value("device", ""), text(claims, "epoch")};
    if (actor.kind == "node") {
        auto row = db.query("SELECT 1 FROM nodes WHERE id=$1 AND epoch=$2 AND status<>'revoked' FOR UPDATE",
                            {actor.id, actor.epoch});
        require(row.size() == 1, "revoked", "Node identity revoked or superseded", 401);
    } else if (actor.kind == "player") {
        auto row = db.query(
            "SELECT COALESCE(extract(epoch FROM valid_until)::bigint,9223372036854775807) FROM devices "
            "WHERE account_id=$1 AND id=$2 AND epoch=$3 AND NOT revoked AND "
            "(valid_until IS NULL OR valid_until>clock_timestamp()) FOR SHARE",
            {actor.id, actor.device, actor.epoch});
        require(row.size() == 1, "revoked", "Device identity revoked or superseded", 401);
        actor.expires = row.number(0);
    } else
        throw Error(401, "unauthorized", "Invalid authorization scope");
    return actor;
}
Reply Service::dispatch(Database &db, const std::string &path, std::string_view bearer, const Json &body) {
    require(body.is_object(), "invalid", "Request must be an object");
    if (path == "/v1/health")
        return {200,
                {{"status", "ready"},
                 {"version", CONTROL_VERSION},
                 {"json_backend", json_backend()},
                 {"protocol", 1},
                 {"signing_public_key", signer_.public_key()},
                 {"openssl_cpu_settings", OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)
                                              ? OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)
                                              : "unavailable"}}};
    Transaction transaction(db);
    if (path == "/v1/enrollment/profile") {
        require(!config_.public_enrollment_credential_file.empty(), "not_found",
                "Public node enrollment is not enabled", 404);
        auto credential = read_secret(config_.public_enrollment_credential_file, 514);
        while (!credential.empty() && (credential.back() == '\n' || credential.back() == '\r'))
            credential.pop_back();
        require(credential.size() >= 32 && credential.size() <= 512, "config",
                "Invalid public enrollment credential", 500);
        require(!secure_equal(sha256(credential), admin_digest_), "config",
                "Administrator authorization cannot be published", 500);
        auto enabled = db.query("SELECT 1 FROM enrollment_credentials WHERE digest=$1 AND enabled",
                                {sha256(credential)});
        require(enabled.size() == 1, "unavailable", "Public node enrollment is disabled", 503);
        return {200,
                {{"protocol", 1}, {"credential", credential}, {"signing_public_key", signer_.public_key()}}};
    }
    Json result;
    if (path.starts_with("/v1/admin/")) {
        require(secure_equal(sha256(bearer), admin_digest_), "unauthorized",
                "Invalid administrator authorization", 401);
        result = admin(db, path, body);
    } else if (path == "/v1/feedback/submit") {
        auto id = text(body, "id", 64), message = text(body, "message", 8000);
        auto contact = body.contains("contact") && body["contact"] != "" ? text(body, "contact", 320) : "";
        auto diagnostics = body.value("diagnostics", Json::object());
        require(diagnostics.is_object() && diagnostics.size() <= 4, "invalid", "Invalid diagnostics");
        for (const auto &[key, value] : diagnostics.items())
            require((key == "application" || key == "version" || key == "system" || key == "architecture") &&
                        value.is_string() && value.get_ref<const std::string &>().size() <= 160,
                    "invalid", "Only basic application and system diagnostics are accepted");
        auto digest =
            sha256(Json{{"message", message}, {"contact", contact}, {"diagnostics", diagnostics}}.dump());
        idempotency_lock(db, "feedback", "submit");
        auto existing = db.query("SELECT digest FROM feedback WHERE id=$1", {id});
        require(!existing.size() || secure_equal(existing.at(0, 0), digest), "conflict",
                "Feedback identifier already used", 409);
        if (!existing.size()) {
            auto count = db.query(
                "SELECT count(*) FROM feedback WHERE created_at>clock_timestamp()-interval '1 hour'");
            require(count.number(0) < 200, "rate_limited", "Feedback is busy; please retry later", 429);
            db.query(
                "INSERT INTO feedback(id,digest,message,contact,diagnostics) VALUES($1,$2,$3,$4,$5::jsonb)",
                {id, digest, message, contact, diagnostics.dump()});
        }
        result = {{"accepted", true}, {"id", id}};
    } else if (path.starts_with("/v1/enrollment/") || path == "/v1/identity/challenge" ||
               path == "/v1/identity/prove") {
        result = enrollment(db, path, body);
    } else {
        auto actor = authenticate(db, bearer);
        auto rate = db.query(R"SQL(INSERT INTO rate_buckets(key,window_id,count)
            VALUES($1,floor(extract(epoch FROM clock_timestamp())/60)::bigint,1)
            ON CONFLICT(key) DO UPDATE SET window_id=excluded.window_id,
            count=CASE WHEN rate_buckets.window_id=excluded.window_id THEN rate_buckets.count+1 ELSE 1 END RETURNING count)SQL",
                             {actor.kind + ":" + actor.id});
        require(rate.number(0) <= config_.heartbeat_limit, "rate_limited", "Request budget exceeded", 429);
        if (path == "/v1/identity/lookup") {
            actor_kind(actor, "player");
            auto identifier = text(body, "identifier", 80);
            auto rows = db.query("SELECT id,username FROM identities WHERE id=$1 OR "
                                 "lower(username)=lower($1) ORDER BY id LIMIT 8",
                                 {identifier});
            Json identities = Json::array();
            for (int i = 0; i < rows.size(); ++i)
                identities.push_back({{"account_id", rows.at(i, 0)}, {"username", rows.at(i, 1)}});
            result = {{"accounts", identities}};
        } else if (path == "/v1/channel/open")
            result = {{"kind", actor.kind}, {"id", actor.id}, {"protocol", 1}};
        else if (path == "/v1/identity/renew") {
            actor_kind(actor, "player");
            result = grant(actor);
        } else if (path.starts_with("/v1/node/"))
            result = node(db, path, body, actor);
        else if (path.starts_with("/v1/placement/") || path.starts_with("/v1/room/"))
            result = placement(db, path, body, actor);
        else if (path.starts_with("/v1/presence/"))
            result = presence(db, path, body, actor);
        else if (path.starts_with("/v1/social/"))
            result = social(db, path, body, actor);
        else
            throw Error(404, "not_found", "Unknown protocol operation");
    }
    require(result.dump().size() <= 262144, "too_large", "Response exceeds protocol budget", 413);
    transaction.commit();
    return {200, std::move(result)};
}
Json Service::admin(Database &db, const std::string &path, const Json &body) {
    if (path == "/v1/admin/feedback/list") {
        auto rows = db.query("SELECT id,message,contact,diagnostics,created_at::text FROM feedback ORDER BY "
                             "created_at DESC LIMIT 20");
        Json items = Json::array();
        for (int i = 0; i < rows.size(); ++i)
            items.push_back({{"id", rows.at(i, 0)},
                             {"message", rows.at(i, 1)},
                             {"contact", rows.at(i, 2)},
                             {"diagnostics", parse_json(rows.at(i, 3))},
                             {"created_at", rows.at(i, 4)}});
        return {{"items", items}};
    }
    if (path == "/v1/admin/device/authorize") {
        auto proof = verify_delegation(body);
        auto expires = integer(body, "expires_at", unix_seconds() + 1, proof.expires);
        idempotency_lock(db, proof.account, "identity");
        db.query("INSERT INTO identities(id,public_key,username) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                 {proof.account, proof.public_key, proof.username});
        auto identity = db.query("SELECT public_key FROM identities WHERE id=$1", {proof.account});
        require(secure_equal(identity.at(0, 0), proof.public_key), "conflict", "Identity key cannot change",
                409);
        auto device = db.query("SELECT revoked,delegation_digest FROM devices WHERE account_id=$1 AND id=$2",
                               {proof.account, proof.device});
        require(!device.size() || (device.at(0, 0) != "t" && device.at(0, 1) == proof.digest), "revoked",
                "Device revoked or delegation changed", 403);
        auto count =
            db.query("SELECT count(*) FROM devices WHERE account_id=$1 AND NOT revoked", {proof.account});
        require(device.size() || count.number(0) < 16, "capacity", "Device limit reached", 409);
        db.query("INSERT INTO devices(account_id,id,epoch,delegation_digest,valid_until) "
                 "VALUES($1,$2,$3,$4,to_timestamp($5::bigint)) ON CONFLICT(account_id,id) "
                 "DO UPDATE SET valid_until=excluded.valid_until",
                 {proof.account, proof.device, random_id(), proof.digest, std::to_string(expires)});
        return {{"authorized", true}, {"expires_at", expires}};
    }
    if (path == "/v1/admin/credential") {
        auto id = text(body, "id", 64), token = text(body, "credential", 512), pool = text(body, "pool", 64);
        require(token.size() >= 32, "invalid", "Enrollment credential must be at least 32 bytes");
        std::string quota = body.contains("quota") ? std::to_string(integer(body, "quota", 1, 100000)) : "";
        db.query(
            R"SQL(INSERT INTO enrollment_credentials(id,digest,pool,quota) VALUES($1,$2,$3,NULLIF($4,'')::integer)
          ON CONFLICT(id) DO UPDATE SET digest=excluded.digest,pool=excluded.pool,quota=excluded.quota,enabled=true)SQL",
            {id, sha256(token), pool, quota});
        db.query("INSERT INTO audit(action,subject) VALUES('credential.rotate',$1)", {id});
        return {{"id", id}, {"pool", pool}, {"expires_at", nullptr}};
    }
    if (path == "/v1/admin/credential/revoke") {
        auto id = text(body, "id", 64);
        db.query("UPDATE enrollment_credentials SET enabled=false WHERE id=$1", {id});
        db.query("INSERT INTO audit(action,subject) VALUES('credential.revoke',$1)", {id});
        return {{"revoked", id}, {"existing_nodes_revoked", false}};
    }
    if (path == "/v1/admin/node") {
        auto id = text(body, "id", 80), status = text(body, "status", 16);
        require(status == "draining" || status == "revoked" || status == "probing", "invalid",
                "Unsupported status");
        auto row =
            db.query("UPDATE nodes SET status=$2,version=version+1 WHERE id=$1 RETURNING id", {id, status});
        require(row.size() == 1, "not_found", "Unknown node", 404);
        db.query("INSERT INTO audit(action,subject) VALUES($1,$2)", {"node." + status, id});
        return {{"id", id}, {"status", status}};
    }
    if (path == "/v1/admin/device/revoke") {
        auto id = text(body, "account_id", 80), device = text(body, "device_id", 64);
        db.query("UPDATE devices SET revoked=true WHERE account_id=$1 AND id=$2", {id, device});
        db.query("INSERT INTO audit(action,subject) VALUES('device.revoke',$1)", {id + ":" + device});
        return {{"revoked", true}};
    }
    throw Error(404, "not_found", "Unknown administrator operation");
}
void Service::maintain(Database &db) {
    Transaction transaction(db);
    db.query("DELETE FROM account_activity_days WHERE (account_id,kind,day) IN "
             "(SELECT account_id,kind,day FROM account_activity_days WHERE day<CURRENT_DATE-400 LIMIT 512)");
    db.query("DELETE FROM browser_values WHERE (kind,id) IN(SELECT kind,id FROM browser_values "
             "WHERE expires_at<clock_timestamp() LIMIT 512 FOR UPDATE SKIP LOCKED)");
    db.query("DELETE FROM feedback WHERE id IN(SELECT id FROM feedback WHERE "
             "created_at<clock_timestamp()-interval '90 days' LIMIT 256)");
    auto rows =
        db.query(R"SQL(SELECT cursor FROM social_events WHERE expires_at<clock_timestamp()-interval '7 days'
         ORDER BY expires_at LIMIT 256 FOR UPDATE SKIP LOCKED)SQL");
    Json cursors = Json::array();
    for (int i = 0; i < rows.size(); ++i)
        cursors.push_back(rows.number(i));
    Params params{cursors.dump()};
    const std::string selection = " IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb))";
    db.query("DELETE FROM delivery_receipts WHERE cursor" + selection, params);
    db.query("DELETE FROM outbox WHERE cursor" + selection, params);
    db.query("DELETE FROM social_events WHERE cursor" + selection, params);
    db.query(
        R"SQL(DELETE FROM challenges WHERE id IN(SELECT id FROM challenges WHERE expires_at<clock_timestamp()-interval '1 hour' LIMIT 256))SQL");
    db.query(
        R"SQL(DELETE FROM sessions WHERE id IN(SELECT id FROM sessions WHERE expires_at<clock_timestamp()-interval '1 day' LIMIT 256))SQL");
    db.query(
        R"SQL(DELETE FROM rate_buckets WHERE key IN(SELECT key FROM rate_buckets WHERE window_id<floor(extract(epoch FROM clock_timestamp())/60)::bigint-2 LIMIT 1024))SQL");
    db.query(
        R"SQL(DELETE FROM audit WHERE cursor IN(SELECT cursor FROM audit WHERE created_at<clock_timestamp()-interval '30 days' LIMIT 256))SQL");
    transaction.commit();
}
} // namespace control
