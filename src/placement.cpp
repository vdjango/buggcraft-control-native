#include "control/service.hpp"
#include <algorithm>
#include <cmath>
#include <map>

namespace control {
namespace {
struct Candidate {
    Json data;
    double rank;
};
// Stable weighted rendezvous. The digest is for distribution only, never an authorization primitive.
double rank_node(const std::string &key, const std::string &node, double weight) {
    auto digest = sha256(key + ":" + node);
    auto bits = std::stoull(digest.substr(0, 13), nullptr, 16);
    auto uniform = (double(bits) + 1.0) / (4503599627370496.0 + 1.0);
    return -std::log(uniform) / std::max(1.0, std::min(weight, 1000.0));
}
} // namespace
Json Service::placement_lease(Database &db, const std::string &path, const Json &body, const Actor &actor,
                              bool active_only) {
    auto id = text(body, "reservation_id", 64);
    auto row = db.query("SELECT node_id FROM reservations WHERE id=$1", {id});
    require(row.size() == 1, "not_found", "Unknown reservation", 404);
    // Capacity mutations lock the node before a reservation everywhere to avoid lock inversion.
    db.query("SELECT id FROM nodes WHERE id=$1 FOR UPDATE", {row.at(0, 0)});
    row = db.query(R"SQL(SELECT actor,node_id,state,room_id,room_epoch,expires_at>clock_timestamp(),ticket
             FROM reservations WHERE id=$1 FOR UPDATE)SQL",
                   {id});
    require(row.size() == 1, "not_found", "Unknown reservation", 404);
    bool node_owner = actor.kind == "node" && actor.id == row.at(0, 1);
    if (path.ends_with("/confirm")) {
        require(node_owner, "forbidden", "Only the assigned node can confirm admission", 403);
        if (active_only)
            require(row.at(0, 2) == "active", "not_active", "Admission must be confirmed first", 409);
        else
            require(secure_equal(text(body, "ticket", 8192), row.at(0, 6)), "forbidden",
                    "Wrong allocation ticket", 403);
        if (body.value("admission", false)) {
            auto ticket = row.at(0, 6);
            auto claims = parse_json(unhex(ticket.substr(0, ticket.find('.'))));
            auto device = db.query("SELECT 1 FROM devices WHERE account_id=$1 AND id=$2 AND NOT revoked "
                                   "AND (valid_until IS NULL OR valid_until>clock_timestamp())",
                                   {row.at(0, 0), text(claims, "device", 64)});
            require(device.size(), "revoked", "Player device authorization revoked", 401);
        }
        require(row.at(0, 2) != "released" && row.at(0, 5) == "t", "expired", "Reservation expired", 409);
        auto room = db.query("SELECT epoch,state FROM rooms WHERE id=$1", {row.at(0, 3)});
        require(room.size() && room.number(0) == row.number(0, 4) && room.at(0, 1) == "open", "stale",
                "Room epoch changed", 409);
        db.query("UPDATE reservations SET state='active',expires_at=clock_timestamp()+interval '120 "
                 "seconds' WHERE id=$1",
                 {id});
        record_activity(db, row.at(0, 0), "multiplayer", 120);
        record_companions(db, row.at(0, 0), row.at(0, 3), row.at(0, 4));
        return {{"reservation_id", id}, {"state", "active"}, {"renew_in", 30}, {"lease_seconds", 120}};
    }
    require(node_owner || (actor.kind == "player" && actor.id == row.at(0, 0)), "forbidden",
            "Not your reservation", 403);
    db.query("UPDATE reservations SET state='released' WHERE id=$1", {id});
    if (row.at(0, 2) == "active") {
        auto remaining = db.query("SELECT 1 FROM reservations WHERE actor=$1 AND state='active' AND "
                                  "expires_at>clock_timestamp() LIMIT 1",
                                  {row.at(0, 0)});
        record_activity(db, row.at(0, 0), "multiplayer", remaining.size() ? 120 : 0);
        db.query(R"SQL(UPDATE companion_activity c SET lease_until=0 WHERE (low_id=$1 OR high_id=$1)
            AND room_id=$2 AND room_epoch=$3::bigint AND NOT EXISTS(
              SELECT 1 FROM reservations a WHERE a.actor=$1 AND a.room_id=$2 AND a.room_epoch=$3::bigint
              AND a.state='active' AND a.expires_at>clock_timestamp()))SQL",
                 {row.at(0, 0), row.at(0, 3), row.at(0, 4)});
    }
    // Releasing the host closes exactly this room generation, never a newer recovery.
    db.query("UPDATE rooms SET state='closed' WHERE reservation_id=$1 AND epoch=$2::bigint",
             {id, row.at(0, 4)});
    return {{"reservation_id", id}, {"state", "released"}};
}
Json Service::placement(Database &db, const std::string &path, const Json &body, const Actor &actor) {
    if (path == "/v1/placement/confirm" || path == "/v1/placement/release")
        return placement_lease(db, path, body, actor);
    if (path == "/v1/placement/refresh") {
        actor_kind(actor, "node");
        const auto &items = body.at("reservations");
        require(items.is_array() && !items.empty() && items.size() <= 256, "invalid",
                "Expected 1-256 active reservations");
        std::map<std::string, bool> actions;
        for (const auto &item : items) {
            auto id = text(item, "reservation_id", 64);
            require(!item.contains("release") || item["release"].is_boolean(), "invalid",
                    "Invalid release action");
            require(actions.emplace(id, item.value("release", false)).second, "invalid",
                    "Duplicate reservation");
        }
        Json results = Json::array();
        for (const auto &[id, release] : actions) {
            // Never acquire another node's lock, and never admit an unconfirmed ticket via refresh.
            auto own = db.query("SELECT 1 FROM reservations WHERE id=$1 AND node_id=$2", {id, actor.id});
            if (!own.size()) {
                results.push_back({{"reservation_id", id}, {"error", "not_found"}});
                continue;
            }
            db.query("SAVEPOINT refresh_item");
            try {
                results.push_back(placement_lease(db,
                                                  release ? "/v1/placement/release" : "/v1/placement/confirm",
                                                  {{"reservation_id", id}}, actor, true));
            } catch (const Error &error) {
                if (error.status >= 500)
                    throw;
                db.query("ROLLBACK TO SAVEPOINT refresh_item");
                results.push_back({{"reservation_id", id}, {"error", error.code}});
            }
            db.query("RELEASE SAVEPOINT refresh_item");
        }
        return {{"reservations", results}, {"lease_seconds", 120}};
    }
    actor_kind(actor, "player");
    if (path == "/v1/room/publish") {
        auto id = text(body, "room_id", 64), reservation = text(body, "reservation_id", 64);
        auto row = db.query(R"SQL(SELECT r.epoch,a.ticket FROM rooms r
          JOIN reservations a ON a.id=r.reservation_id
          WHERE r.id=$1 AND r.owner_account=$2 AND r.reservation_id=$3 AND r.state='open'
          AND a.state='active' AND a.expires_at>clock_timestamp() FOR UPDATE OF r)SQL",
                            {id, actor.id, reservation});
        require(row.size(), "not_found", "Room unavailable", 404);
        auto ticket = row.at(0, 1);
        auto claims = parse_json(unhex(ticket.substr(0, ticket.find('.'))));
        require(claims.value("device", "") == actor.device, "forbidden", "Room host device required", 403);
        require(integer(body, "room_epoch", 1, INT64_MAX) == row.number(0), "stale", "Room epoch changed",
                409);
        auto secret = text(body, "secret", 128);
        require(secret.size() >= 32 && sha256(secret).substr(0, 32) == id, "invalid",
                "Invalid room invitation");
        const auto &info = body.at("room");
        require(info.is_object() && info.contains("public") && info["public"].is_boolean() &&
                    info.contains("require_invite") && info["require_invite"].is_boolean(),
                "invalid", "Explicit room access policy required");
        auto title = text(info, "title", 320);
        auto availability = text(info, "availability", 16);
        require(availability == "ready" || availability == "waiting", "invalid", "Invalid room availability");
        auto game = info.value("game", Json::object());
        require(game.is_object() && game.dump().size() <= 4096, "invalid", "Invalid room game metadata");
        Json listing = {{"title", title},
                        {"public", info["public"]},
                        {"require_invite", !info["public"].get<bool>() || info["require_invite"].get<bool>()},
                        {"availability", availability},
                        {"game", game},
                        {"connections", integer(info, "connections", 0, 100000)},
                        {"capacity", integer(info, "capacity", 0, 100000)}};
        db.query("UPDATE rooms SET listing=$2::jsonb,secret=$3 WHERE id=$1", {id, listing.dump(), secret});
        return {{"published", true}};
    }
    if (path == "/v1/placement/reconnect") {
        auto id = text(body, "reservation_id", 64);
        auto row = db.query(
            "SELECT actor,ticket,state,expires_at>clock_timestamp() FROM reservations WHERE id=$1 FOR UPDATE",
            {id});
        require(row.size() && row.at(0, 0) == actor.id, "forbidden", "Allocation owner required", 403);
        require(row.at(0, 2) == "active" && row.at(0, 3) == "t", "expired", "Allocation expired", 409);
        auto old = row.at(0, 1);
        auto claims = parse_json(unhex(old.substr(0, old.find('.'))));
        require(claims.value("device", "") == actor.device, "forbidden", "Allocation device required", 403);
        claims["exp"] = unix_seconds() + config_.reservation_seconds;
        auto ticket = signer_.token(claims);
        db.query("UPDATE reservations SET ticket=$2 WHERE id=$1", {id, ticket});
        return {{"reservation_id", id}, {"ticket", ticket}};
    }
    if (path == "/v1/room/list") {
        auto query = body.value("query", std::string{});
        require(query.size() <= 400, "invalid", "Room search too long");
        auto rows = db.query(R"SQL(SELECT r.id,r.owner_account,r.epoch,r.listing,n.region FROM rooms r
            JOIN reservations a ON a.id=r.reservation_id JOIN nodes n ON n.id=r.node_id
            WHERE r.state='open' AND a.state='active' AND a.expires_at>clock_timestamp()
            AND n.status='active' AND n.health_until>clock_timestamp() AND r.listing->>'public'='true'
            AND strpos(lower(r.listing->>'title'),lower($1))>0 ORDER BY r.id LIMIT 50)SQL",
                             {query});
        Json rooms = Json::array();
        for (int i = 0; i < rows.size(); ++i) {
            auto listing = rows.json(i, 3);
            listing.update({{"id", rows.at(i, 0)},
                            {"owner", rows.at(i, 1)},
                            {"room_epoch", rows.number(i, 2)},
                            {"node_region", rows.at(i, 4)}});
            rooms.push_back(std::move(listing));
        }
        return {{"rooms", rooms}, {"managed", true}};
    }
    if (path == "/v1/room/locate" || path == "/v1/room/inspect" || path == "/v1/room/resolve") {
        auto id = text(body, "room_id", 64);
        auto room = db.query(R"SQL(SELECT r.owner_account,r.node_id,r.epoch,r.state,n.endpoint,n.public_key,
          EXISTS(SELECT 1 FROM reservations a WHERE a.id=r.reservation_id AND a.state<>'released' AND a.expires_at>clock_timestamp()),
          coalesce(r.listing,'{}'),coalesce(r.secret,''),n.status='active' AND n.health_until>clock_timestamp()
          FROM rooms r JOIN nodes n ON n.id=r.node_id WHERE r.id=$1)SQL",
                             {id});
        require(room.size() == 1 && room.at(0, 3) == "open" && room.at(0, 6) == "t", "not_found",
                "Room unavailable", 404);
        require(room.at(0, 9) == "t", "node_unavailable", "Room node temporarily unavailable", 503);
        if (path.ends_with("/inspect")) {
            auto friend_row = db.query("SELECT 1 FROM friendships WHERE low_id=LEAST($1,$2) AND "
                                       "high_id=GREATEST($1,$2) AND state='accepted'",
                                       {actor.id, room.at(0, 0)});
            require(room.at(0, 0) == actor.id || friend_row.size(), "forbidden",
                    "Friend relationship required", 403);
            return {{"room_id", id}, {"epoch", room.number(0, 2)}};
        }
        auto listing = room.json(0, 7);
        const bool freely_joinable = listing.value("public", false) && !listing.value("require_invite", true);
        if (room.at(0, 0) != actor.id && !freely_joinable) {
            auto invited = db.query(
                R"SQL(SELECT 1 FROM social_events WHERE target=$1 AND actor=$2 AND kind IN('invite','join_accept')
                AND body->>'room_id'=$3 AND body->>'room_epoch'=$4 AND expires_at>clock_timestamp() LIMIT 1)SQL",
                {actor.id, room.at(0, 0), id, room.at(0, 2)});
            require(invited.size() == 1, "invitation_required", "Room invitation required", 403);
        }
        if (path.ends_with("/resolve")) {
            require(!room.at(0, 8).empty(), "unpublished",
                    "Room invitation not published; ask the host for an invitation", 409);
            return {{"secret", room.at(0, 8)}, {"room", listing}};
        }
        return {{"room_id", id},
                {"node_id", room.at(0, 1)},
                {"epoch", room.number(0, 2)},
                {"endpoint", room.at(0, 4)},
                {"public_key", room.at(0, 5)}};
    }
    if (path == "/v1/placement/candidates") {
        auto region = text(body, "region", 64), op = text(body, "operator", 64);
        Json regions = Json::array({region});
        if (body.contains("nearby")) {
            require(body["nearby"].is_array() && body["nearby"].size() <= 3, "invalid",
                    "Too many fallback regions");
            for (const auto &r : body["nearby"]) {
                require(r.is_string() && r.get<std::string>().size() <= 64, "invalid",
                        "Invalid fallback region");
                // A hint cannot authorize arbitrary cross-region spillover.
                if (config_.region_routes.contains(region) &&
                    std::find(config_.region_routes[region].begin(), config_.region_routes[region].end(),
                              r) != config_.region_routes[region].end())
                    regions.push_back(r);
            }
        }
        auto start_shard = std::to_string(std::stoul(sha256(actor.id).substr(0, 4), nullptr, 16) % 64);
        // Rotated indexed shards prevent a fixed LIMIT from permanently starving all but the first nodes.
        // LATERAL keeps each bucket bounded; no full-world sort or directory download.
        auto rows = db.query(
            R"SQL(SELECT jsonb_build_object('node_id',n.id,'region',n.region,'operator',n.operator,
             'endpoint',n.endpoint,'public_key',n.public_key,'slots',n.slots,'version',n.version)
             FROM jsonb_array_elements_text($1::jsonb) AS r(region)
             CROSS JOIN generate_series(0,63) AS s(offset_id)
             CROSS JOIN jsonb_array_elements_text($3::jsonb) AS p(pool)
             CROSS JOIN LATERAL (
               (SELECT * FROM nodes WHERE pool=p.pool AND region=r.region
                AND shard=mod($2::integer+s.offset_id,64) AND status='active' AND health_until>clock_timestamp()
                AND observed_slots<slots AND observed_bandwidth<bandwidth AND id>=$4 ORDER BY id LIMIT 8)
               UNION ALL
               (SELECT * FROM nodes WHERE pool=p.pool AND region=r.region
                AND shard=mod($2::integer+s.offset_id,64) AND status='active' AND health_until>clock_timestamp()
                AND observed_slots<slots AND observed_bandwidth<bandwidth AND id<$4 ORDER BY id LIMIT 8)
             ) n LIMIT 128)SQL",
            {regions.dump(), start_shard, config_.allowed_pools.dump(), "n_" + sha256(actor.id + ":cursor")});
        std::vector<Candidate> candidates;
        for (int i = 0; i < rows.size(); ++i) {
            auto data = rows.json(i);
            double preference = (data["region"] == region ? 1.0 : 0.1) * (data["operator"] == op ? 1.2 : 1.0);
            candidates.push_back(
                {data, rank_node(actor.id, data["node_id"],
                                 std::min(1000.0, double(data["slots"].get<int>())) * preference)});
        }
        std::sort(candidates.begin(), candidates.end(),
                  [](const auto &a, const auto &b) { return a.rank < b.rank; });
        Json result = Json::array(), ids = Json::array();
        for (std::size_t i = 0; i < candidates.size() && i < config_.candidate_limit; ++i) {
            result.push_back(candidates[i].data);
            ids.push_back(candidates[i].data["node_id"]);
        }
        return {{"candidates", result},
                {"probe_token", signer_.token({{"aud", config_.audience + ":probe"},
                                               {"sub", actor.id},
                                               {"nodes", ids},
                                               {"exp", unix_seconds() + 30}})},
                {"max_concurrent_probes", 3}};
    }
    if (path != "/v1/placement/reserve")
        throw Error(404, "not_found", "Unknown placement operation");
    auto idem = text(body, "idempotency_key", 64), digest = sha256(body.dump());
    idempotency_lock(db, actor.id, "allocations");
    idempotency_lock(db, actor.id, idem);
    auto existing = db.query("SELECT digest,id,ticket,state FROM reservations WHERE actor=$1 AND idem=$2",
                             {actor.id, idem});
    if (existing.size()) {
        require(existing.at(0, 0) == digest, "conflict", "Idempotency key reused with different request",
                409);
        return {{"reservation_id", existing.at(0, 1)},
                {"ticket", existing.at(0, 2)},
                {"state", existing.at(0, 3)}};
    }
    auto room_id = text(body, "room_id", 64), intent = text(body, "intent", 8);
    auto account_budget = db.query("SELECT count(*) FROM reservations WHERE actor=$1 AND state<>'released' "
                                   "AND expires_at>clock_timestamp()",
                                   {actor.id});
    require(account_budget.number(0) < 8, "capacity", "Player allocation budget exhausted", 409);
    require(intent == "new" || intent == "join" || intent == "recover", "invalid",
            "Unknown allocation intent");
    // Serialize room creation/recovery across processes, including the absence of a row.
    idempotency_lock(db, "room", room_id);
    auto room = db.query(
        "SELECT owner_account,node_id,epoch,state,reservation_id,coalesce(listing,'{}'),coalesce(secret,'') "
        "FROM rooms WHERE id=$1",
        {room_id});
    std::int64_t epoch = 1;
    std::vector<std::string> nodes;
    if (intent == "join") {
        require(room.size() && room.at(0, 3) == "open", "not_found", "Room unavailable", 404);
        epoch = room.number(0, 2);
        nodes.push_back(room.at(0, 1));
        auto host_active = db.query(
            "SELECT 1 FROM reservations WHERE id=$1 AND state<>'released' AND expires_at>clock_timestamp()",
            {room.at(0, 4)});
        require(host_active.size() == 1, "expired", "Room host allocation expired", 409);
        auto invited = db.query(
            R"SQL(SELECT 1 FROM social_events WHERE target=$1 AND actor=$2 AND kind IN('invite','join_accept')
                AND body->>'room_id'=$3 AND body->>'room_epoch'=$4 AND expires_at>clock_timestamp() LIMIT 1)SQL",
            {actor.id, room.at(0, 0), room_id, std::to_string(epoch)});
        const auto listing = room.json(0, 5);
        const auto secret = body.value("secret", std::string{});
        const bool copied_invite =
            secret.size() >= 32 && secret.size() <= 128 && sha256(secret).substr(0, 32) == room_id;
        require(invited.size() || room.at(0, 0) == actor.id || copied_invite ||
                    (listing.value("public", false) && !listing.value("require_invite", true)),
                "invitation_required", "Room invitation required", 403);
    } else {
        require(!room.size() || (intent == "recover" && room.at(0, 0) == actor.id), "conflict",
                "Room already exists", 409);
        if (room.size())
            epoch = room.number(0, 2) + 1;
        auto probe = signer_.verify(text(body, "probe_token", 8192), config_.audience + ":probe");
        require(probe.value("sub", "") == actor.id, "forbidden", "Probe ticket belongs to another player",
                403);
        require(body.contains("measurements") && body["measurements"].is_array() &&
                    body["measurements"].size() <= 8,
                "invalid", "Measurements required");
        std::map<std::string, std::int64_t> latency;
        for (const auto &m : body["measurements"]) {
            auto id = text(m, "node_id", 80);
            require(std::find(probe["nodes"].begin(), probe["nodes"].end(), Json(id)) != probe["nodes"].end(),
                    "forbidden", "Node not in candidate ticket", 403);
            require(!latency.contains(id), "invalid", "Duplicate measurement");
            latency[id] = integer(m, "rtt_ms", 1, 10000);
        }
        require(!latency.empty(), "capacity", "No reachable candidate", 409);
        auto best = std::min_element(latency.begin(), latency.end(), [](const auto &a, const auto &b) {
                        return a.second < b.second;
                    })->second;
        std::vector<std::pair<double, std::string>> ranked;
        for (const auto &[id, rtt] : latency) {
            if (rtt > best + 20)
                continue;
            auto capacity = db.query("SELECT slots-observed_slots FROM nodes WHERE id=$1", {id});
            if (capacity.size())
                ranked.emplace_back(rank_node(actor.id + ":" + room_id, id, double(capacity.number(0))), id);
        }
        std::sort(ranked.begin(), ranked.end());
        for (auto &candidate : ranked)
            nodes.push_back(candidate.second);
    }
    auto slots = integer(body, "slots", 1, 64), bandwidth = integer(body, "bandwidth", 1, 1000000000);
    for (const auto &id : nodes) {
        db.query("SAVEPOINT candidate");
        auto node_row = db.query(
            R"SQL(SELECT slots,bandwidth,observed_slots,observed_bandwidth,endpoint,public_key,version
            FROM nodes WHERE id=$1 AND pool IN(SELECT jsonb_array_elements_text($2::jsonb)) AND status='active'
            AND health_until>clock_timestamp() FOR UPDATE)SQL",
            {id, config_.allowed_pools.dump()});
        if (!node_row.size()) {
            db.query("ROLLBACK TO SAVEPOINT candidate");
            continue;
        }
        auto used = db.query(R"SQL(SELECT coalesce(sum(slots) FILTER(WHERE state='active'),0),
            coalesce(sum(slots) FILTER(WHERE state='pending'),0),
            coalesce(sum(bandwidth) FILTER(WHERE state='active'),0),
            coalesce(sum(bandwidth) FILTER(WHERE state='pending'),0)
            FROM reservations WHERE node_id=$1 AND state<>'released' AND expires_at>clock_timestamp())SQL",
                             {id});
        auto used_slots = std::max(used.number(0, 0), node_row.number(0, 2)) + used.number(0, 1);
        auto used_bandwidth = std::max(used.number(0, 2), node_row.number(0, 3)) + used.number(0, 3);
        if (used_slots + slots > node_row.number(0, 0) ||
            used_bandwidth + bandwidth > node_row.number(0, 1)) {
            db.query("ROLLBACK TO SAVEPOINT candidate");
            continue;
        }
        auto reservation = random_id();
        auto ticket = signer_.token({{"aud", config_.audience + ":allocation"},
                                     {"sub", actor.id},
                                     {"device", actor.device},
                                     {"node_id", id},
                                     {"public_key", node_row.at(0, 5)},
                                     {"endpoint", node_row.at(0, 4)},
                                     {"room_id", room_id},
                                     {"room_epoch", epoch},
                                     {"intent", intent},
                                     {"reservation_id", reservation},
                                     {"slots", slots},
                                     {"bandwidth", bandwidth},
                                     {"version", node_row.number(0, 6)},
                                     {"exp", unix_seconds() + config_.reservation_seconds}});
        db.query(
            R"SQL(INSERT INTO reservations(id,actor,idem,digest,node_id,room_id,room_epoch,slots,bandwidth,expires_at,ticket)
            VALUES($1,$2,$3,$4,$5,$6,$7::bigint,$8::integer,$9::bigint,
            clock_timestamp()+$10::integer*interval '1 second',$11))SQL",
            {reservation, actor.id, idem, digest, id, room_id, std::to_string(epoch), std::to_string(slots),
             std::to_string(bandwidth), std::to_string(config_.reservation_seconds), ticket});
        if (intent != "join") {
            db.query(
                R"SQL(INSERT INTO rooms(id,owner_account,node_id,epoch,reservation_id) VALUES($1,$2,$3,$4::bigint,$5)
                ON CONFLICT(id) DO UPDATE SET node_id=excluded.node_id,epoch=excluded.epoch,
                reservation_id=excluded.reservation_id,state='open',listing=NULL,secret=NULL)SQL",
                {room_id, actor.id, id, std::to_string(epoch), reservation});
        }
        return {{"reservation_id", reservation},
                {"ticket", ticket},
                {"node_id", id},
                {"room_id", room_id},
                {"room_epoch", epoch},
                {"endpoint", node_row.at(0, 4)},
                {"state", "pending"}};
    }
    throw Error(409, "capacity", "No eligible node has enough capacity; retry with backoff");
}
} // namespace control
