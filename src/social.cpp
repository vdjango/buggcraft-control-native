#include "control/service.hpp"
#include <algorithm>
#include <set>

namespace control {
Json Service::presence(Database &db, const std::string &path, const Json &body, const Actor &actor) {
    actor_kind(actor, "player");
    if (path == "/v1/presence/open") {
        auto idem = text(body, "idempotency_key", 64);
        idempotency_lock(db, actor.id, "presence:" + actor.device);
        auto count = db.query("SELECT count(*) FROM sessions WHERE account_id=$1 AND state='online' AND "
                              "expires_at>clock_timestamp()",
                              {actor.id});
        auto existing =
            db.query("SELECT id,epoch FROM sessions WHERE account_id=$1 AND device_id=$2 AND idem=$3",
                     {actor.id, actor.device, idem});
        if (existing.size()) {
            require(existing.at(0, 1) == actor.epoch, "stale", "Session belongs to a previous device epoch",
                    409);
            return {{"session_id", existing.at(0, 0)},
                    {"epoch", actor.epoch},
                    {"lease_seconds", config_.player_lease_seconds}};
        }
        require(count.number(0) < 32, "capacity", "Session limit reached", 409);
        auto id = random_id();
        db.query(
            R"SQL(INSERT INTO sessions(id,account_id,device_id,epoch,idem,expires_at)
             VALUES($1,$2,$3,$4,$5,clock_timestamp()+$6::integer*interval '1 second'))SQL",
            {id, actor.id, actor.device, actor.epoch, idem, std::to_string(config_.player_lease_seconds)});
        record_activity(db, actor.id, "online", config_.player_lease_seconds);
        return {{"session_id", id}, {"epoch", actor.epoch}, {"lease_seconds", config_.player_lease_seconds}};
    }
    if (path == "/v1/presence/refresh" || path == "/v1/presence/close") {
        auto session = text(body, "session_id", 64),
             sequence = std::to_string(integer(body, "sequence", 1, INT64_MAX));
        auto state = path.ends_with("/close") ? "offline" : "online";
        auto row = db.query(R"SQL(UPDATE sessions SET sequence=$5::bigint,state=$6,
            expires_at=clock_timestamp()+$7::integer*interval '1 second'
            WHERE id=$1 AND account_id=$2 AND device_id=$3 AND epoch=$4 AND state<>'offline' AND sequence<$5::bigint
            RETURNING id)SQL",
                            {session, actor.id, actor.device, actor.epoch, sequence, state,
                             std::to_string(config_.player_lease_seconds)});
        require(row.size(), "stale", "Stale or closed session", 409);
        auto remaining = db.query("SELECT 1 FROM sessions WHERE account_id=$1 AND state='online' AND "
                                  "expires_at>clock_timestamp() LIMIT 1",
                                  {actor.id});
        record_activity(db, actor.id, "online", remaining.size() ? config_.player_lease_seconds : 0);
        return {{"session_id", session}, {"state", state}, {"sequence", std::stoll(sequence)}};
    }
    if (path == "/v1/presence/view") {
        auto target = text(body, "account_id", 80);
        if (target != actor.id) {
            auto friendship = db.query("SELECT 1 FROM friendships WHERE low_id=LEAST($1,$2) AND "
                                       "high_id=GREATEST($1,$2) AND state='accepted'",
                                       {actor.id, target});
            require(friendship.size(), "forbidden", "Presence is visible to friends only", 403);
        }
        auto rows = db.query(R"SQL(SELECT
            count(*) FILTER(WHERE s.state='online' AND s.expires_at>clock_timestamp()),
            count(*) FILTER(WHERE s.state='online'),count(*) FROM sessions s JOIN devices d
            ON d.account_id=s.account_id AND d.id=s.device_id AND d.epoch=s.epoch
            WHERE s.account_id=$1 AND NOT d.revoked)SQL",
                             {target});
        std::string state = rows.number(0, 0)                         ? "online"
                            : rows.number(0, 1) || !rows.number(0, 2) ? "unknown"
                                                                      : "offline";
        return {{"account_id", target}, {"state", state}, {"active_sessions", rows.number(0)}};
    }
    throw Error(404, "not_found", "Unknown presence operation");
}
Json Service::social(Database &db, const std::string &path, const Json &body, const Actor &actor) {
    actor_kind(actor, "player");
    if (path == "/v1/social/state") {
        auto relations = db.query(R"SQL(SELECT CASE WHEN f.low_id=$1 THEN f.high_id ELSE f.low_id END,
            f.state,f.requested_by,coalesce(i.username,''),
            CASE WHEN p.active>0 THEN 'online' WHEN p.online_count>0 OR p.total=0 THEN 'unknown' ELSE 'offline' END,
            (SELECT jsonb_build_object('id',r.id,'title',coalesce(i.username,''),'epoch',r.epoch,'availability','unknown')
             FROM rooms r JOIN reservations a ON a.id=r.reservation_id WHERE r.owner_account=i.id
             AND r.state='open' AND a.state<>'released' AND a.expires_at>clock_timestamp() ORDER BY r.id LIMIT 1)
            FROM friendships f JOIN identities i
            ON i.id=CASE WHEN f.low_id=$1 THEN f.high_id ELSE f.low_id END
            CROSS JOIN LATERAL(SELECT count(*) FILTER(WHERE s.state='online' AND s.expires_at>clock_timestamp()) active,
                count(*) FILTER(WHERE s.state='online') online_count,count(*) total FROM sessions s JOIN devices d
                ON d.account_id=s.account_id AND d.id=s.device_id AND d.epoch=s.epoch
                WHERE s.account_id=i.id AND NOT d.revoked AND (d.valid_until IS NULL OR d.valid_until>clock_timestamp())) p
            WHERE (f.low_id=$1 OR f.high_id=$1) AND f.state<>'rejected' ORDER BY i.id LIMIT 256)SQL",
                                  {actor.id});
        Json friends = Json::array(), requests = Json::array();
        for (int i = 0; i < relations.size(); ++i) {
            auto id = relations.at(i, 0);
            Json item = {{"id", id}, {"account", id}, {"username", relations.at(i, 3)}};
            if (relations.at(i, 1) == "accepted") {
                item["online"] = relations.at(i, 4) == "online";
                item["presenceState"] = relations.at(i, 4);
                item["room"] = relations.at(i, 5).empty() ? Json(nullptr) : relations.json(i, 5);
                friends.push_back(item);
            } else {
                item["incoming"] = relations.at(i, 2) != actor.id;
                requests.push_back(item);
            }
        }
        auto inbox = db.query(R"SQL(SELECT e.actor,coalesce(i.username,''),e.event_id,e.kind,e.body,
            extract(epoch FROM e.expires_at)::bigint FROM social_events e JOIN identities i ON i.id=e.actor
            JOIN rooms room ON room.id=e.body->>'room_id' AND room.epoch=(e.body->>'room_epoch')::bigint
            JOIN reservations allocation ON allocation.id=room.reservation_id
            WHERE e.target=$1 AND e.expires_at>clock_timestamp() AND room.state='open'
            AND allocation.state<>'released' AND allocation.expires_at>clock_timestamp()
            AND e.kind IN('invite','join_request','join_accept')
            ORDER BY e.cursor DESC LIMIT 64)SQL",
                              {actor.id});
        Json invites = Json::array(), joins = Json::array();
        for (int i = 0; i < inbox.size(); ++i) {
            auto data = inbox.json(i, 4);
            Json item = {{"account", inbox.at(i, 0)},
                         {"username", inbox.at(i, 1)},
                         {"id", inbox.at(i, 2)},
                         {"room", data.value("room_id", "")},
                         {"room_epoch", data.value("room_epoch", 0)},
                         {"expires", inbox.number(i, 5)},
                         {"incoming", true}};
            if (data.contains("invite"))
                item["invite"] = data["invite"];
            if (inbox.at(i, 3) == "join_request")
                joins.push_back(item);
            else
                invites.push_back(item);
        }
        auto receipts = db.query(R"SQL(SELECT e.event_id,
            CASE WHEN bool_or(r.seen) THEN 'seen' WHEN bool_or(r.delivered) THEN 'delivered' ELSE 'accepted' END,
            extract(epoch FROM e.expires_at)::bigint FROM social_events e
            LEFT JOIN delivery_receipts r ON r.cursor=e.cursor AND r.account_id=e.target
            WHERE e.actor=$1 AND e.expires_at>clock_timestamp()
            GROUP BY e.cursor,e.event_id,e.expires_at ORDER BY e.cursor DESC LIMIT 64)SQL",
                                 {actor.id});
        Json deliveries = Json::array();
        for (int i = 0; i < receipts.size(); ++i)
            deliveries.push_back({{"id", receipts.at(i, 0)},
                                  {"state", receipts.at(i, 1)},
                                  {"expires", receipts.number(i, 2)}});
        auto own = db.query("SELECT coalesce(username,'') FROM identities WHERE id=$1", {actor.id});
        return {{"account", actor.id},
                {"username", own.at(0, 0)},
                {"friends", friends},
                {"requests", requests},
                {"invitations", invites},
                {"joinRequests", joins},
                {"deliveries", deliveries},
                {"capabilities", {{"presence_state", true}, {"reliable_delivery", true}}}};
    }
    if (path == "/v1/social/inbox") {
        auto after = integer(body, "after", 0, INT64_MAX);
        auto rows =
            db.query(R"SQL(SELECT jsonb_build_object('cursor',e.cursor,'actor',e.actor,'event_id',e.event_id,
            'kind',e.kind,'body',e.body,'expires_at',extract(epoch FROM e.expires_at)::bigint,
            'delivered',coalesce(r.delivered,false),'seen',coalesce(r.seen,false))
            FROM outbox o JOIN social_events e ON e.cursor=o.cursor
            LEFT JOIN delivery_receipts r ON r.cursor=e.cursor AND r.account_id=$1 AND r.device_id=$3
            WHERE o.target=$1 AND e.cursor>$2::bigint AND e.expires_at>clock_timestamp()
            ORDER BY e.cursor LIMIT 64)SQL",
                     {actor.id, std::to_string(after), actor.device});
        Json events = Json::array();
        for (int i = 0; i < rows.size(); ++i)
            events.push_back(rows.json(i));
        return {{"events", events},
                {"cursor", events.empty() ? after : events.back()["cursor"].get<std::int64_t>()},
                {"has_more", events.size() == 64}};
    }
    if (path == "/v1/social/ack") {
        Json cursors = body.contains("cursors") ? body.at("cursors")
                                                : Json::array({integer(body, "cursor", 1, INT64_MAX)});
        require(cursors.is_array() && !cursors.empty() && cursors.size() <= 64, "invalid",
                "Receipt batch exceeds budget");
        std::set<int64_t> unique;
        for (const auto &cursor : cursors) {
            require(cursor.is_number_integer() && cursor.get<int64_t>() > 0, "invalid",
                    "Invalid receipt cursor");
            unique.insert(cursor.get<int64_t>());
        }
        auto state = text(body, "state", 16);
        require(state == "delivered" || state == "seen", "invalid", "Unknown receipt state");
        auto event = db.query("SELECT cursor FROM social_events WHERE cursor IN(SELECT value::bigint FROM "
                              "jsonb_array_elements_text($1::jsonb)) AND target=$2",
                              {cursors.dump(), actor.id});
        require(event.size() == static_cast<int>(unique.size()), "forbidden", "Not your event", 403);
        db.query(R"SQL(INSERT INTO delivery_receipts(cursor,account_id,device_id,delivered,seen)
            SELECT DISTINCT value::bigint,$2,$3,true,$4::boolean FROM jsonb_array_elements_text($1::jsonb)
            ON CONFLICT(cursor,account_id,device_id)
            DO UPDATE SET delivered=true,seen=delivery_receipts.seen OR excluded.seen)SQL",
                 {cursors.dump(), actor.id, actor.device, state == "seen" ? "true" : "false"});
        if (body.contains("cursors"))
            return {{"cursors", cursors}, {"state", state}};
        return {{"cursor", cursors.at(0)}, {"state", state}};
    }
    if (path != "/v1/social/apply")
        throw Error(404, "not_found", "Unknown social operation");
    require(body.dump().size() <= 2048, "too_large", "Social event exceeds budget", 413);
    auto id = text(body, "event_id", 64), target = text(body, "target", 80), kind = text(body, "kind", 32);
    const std::set<std::string> kinds = {"friend_request", "friend_accept", "friend_reject",
                                         "invite",         "invite_revoke", "join_request",
                                         "join_accept",    "join_reject",   "friend_remove"};
    require(kinds.contains(kind) && target != actor.id, "invalid", "Invalid social event");
    auto digest = sha256(body.dump());
    idempotency_lock(db, actor.id, "event:" + id);
    auto existing =
        db.query("SELECT digest,cursor FROM social_events WHERE actor=$1 AND event_id=$2", {actor.id, id});
    if (existing.size()) {
        require(existing.at(0, 0) == digest, "conflict", "Event ID reused with different content", 409);
        return {{"event_id", id}, {"cursor", existing.number(0, 1)}, {"state", "accepted"}};
    }
    auto identity = db.query("SELECT 1 FROM identities WHERE id=$1", {target});
    require(identity.size(), "not_found", "Unknown target identity", 404);
    // Serializes relationship transitions and bounded inbox admission for each recipient.
    idempotency_lock(db, "social", std::min(actor.id, target) + ":" + std::max(actor.id, target));
    idempotency_lock(db, "inbox", target);
    auto pending = db.query(R"SQL(SELECT count(*) FROM outbox o JOIN social_events e ON e.cursor=o.cursor
        WHERE o.target=$1 AND e.expires_at>clock_timestamp() AND NOT EXISTS
        (SELECT 1 FROM delivery_receipts r WHERE r.cursor=e.cursor AND r.account_id=$1 AND r.delivered))SQL",
                            {target});
    require(pending.number(0) < 256, "capacity", "Recipient inbox budget exhausted", 429);
    auto friendship = db.query(
        "SELECT state,requested_by FROM friendships WHERE low_id=LEAST($1,$2) AND high_id=GREATEST($1,$2)",
        {actor.id, target});
    int ttl = 120;
    if (kind == "friend_request") {
        require(!friendship.size() || friendship.at(0, 0) == "rejected", "conflict",
                "Relationship already exists", 409);
        db.query(
            R"SQL(INSERT INTO friendships(low_id,high_id,requested_by,state) VALUES(LEAST($1,$2),GREATEST($1,$2),$1,'pending')
           ON CONFLICT(low_id,high_id) DO UPDATE SET requested_by=$1,state='pending')SQL",
            {actor.id, target});
        ttl = 604800;
    } else if (kind == "friend_accept" || kind == "friend_reject") {
        require(friendship.size() && friendship.at(0, 0) == "pending" && friendship.at(0, 1) == target,
                "forbidden", "No incoming friend request", 403);
        db.query("UPDATE friendships SET state=$3 WHERE low_id=LEAST($1,$2) AND high_id=GREATEST($1,$2)",
                 {actor.id, target, kind == "friend_accept" ? "accepted" : "rejected"});
        ttl = 604800;
    } else if (kind == "friend_remove") {
        require(friendship.size(), "not_found", "Friend relationship not found", 404);
        db.query(
            "UPDATE friendships SET state='rejected' WHERE low_id=LEAST($1,$2) AND high_id=GREATEST($1,$2)",
            {actor.id, target});
        ttl = 604800;
    } else {
        require(friendship.size() && friendship.at(0, 0) == "accepted", "forbidden",
                "Friend relationship required", 403);
        auto room_id = text(body, "room_id", 64),
             epoch = std::to_string(integer(body, "room_epoch", 1, INT64_MAX));
        auto room =
            db.query(R"SQL(SELECT r.owner_account FROM rooms r JOIN reservations a ON a.id=r.reservation_id
            WHERE r.id=$1 AND r.epoch=$2::bigint AND r.state='open' AND a.state<>'released'
            AND a.expires_at>clock_timestamp())SQL",
                     {room_id, epoch});
        require(room.size(), "stale", "Room unavailable or epoch changed", 409);
        if (kind == "join_request")
            require(room.at(0, 0) == target, "forbidden", "Join request must target the owner", 403);
        else
            require(room.at(0, 0) == actor.id, "forbidden", "Only the room owner can send this event", 403);
        if (kind == "invite_revoke") {
            auto original = text(body, "invite_event_id", 64);
            db.query("UPDATE social_events SET expires_at=clock_timestamp() WHERE actor=$1 AND target=$2 AND "
                     "event_id=$3 AND kind='invite' AND body->>'room_id'=$4 AND body->>'room_epoch'=$5",
                     {actor.id, target, original, room_id, epoch});
        }
        if (kind == "join_accept" || kind == "join_reject") {
            auto original = text(body, "request_event_id", 64);
            auto request =
                db.query(R"SQL(SELECT 1 FROM social_events WHERE actor=$1 AND target=$2 AND event_id=$3
                AND kind='join_request' AND body->>'room_id'=$4 AND body->>'room_epoch'=$5 AND expires_at>clock_timestamp())SQL",
                         {target, actor.id, original, room_id, epoch});
            require(request.size(), "expired", "Join request expired or unknown", 409);
            db.query("UPDATE social_events SET expires_at=clock_timestamp() WHERE actor=$1 AND event_id=$2",
                     {target, original});
        }
        ttl = kind == "invite" || kind == "join_accept" ? 300 : 120;
    }
    // Sequence numbers alone can commit out of order and cause a cursor reader to skip an event.
    // Only final publication through commit is serialized; inbox readers do not take this lock.
    idempotency_lock(db, "social-cursor", "publication");
    auto event =
        db.query(R"SQL(INSERT INTO social_events(actor,event_id,target,device_id,kind,digest,body,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,clock_timestamp()+$8::integer*interval '1 second') RETURNING cursor)SQL",
                 {actor.id, id, target, actor.device, kind, digest, body.dump(), std::to_string(ttl)});
    db.query("INSERT INTO outbox(cursor,target) VALUES($1::bigint,$2)", {event.at(0, 0), target});
    return {{"event_id", id}, {"cursor", event.number(0)}, {"state", "accepted"}, {"expires_in", ttl}};
}
} // namespace control
