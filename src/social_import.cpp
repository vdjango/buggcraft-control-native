#include "control/service.hpp"
#include <algorithm>
#include <map>
#include <set>

namespace control {
// Offline, operator-owned conversion. Signed historical grants may be expired;
// signatures and their validity at the event time are still mandatory.
Json Service::import_social(Database &db, const Json &events) {
    require(config_.browser && events.is_array() && events.size() <= 200000, "invalid",
            "Invalid signed social snapshot");
    Transaction transaction(db);
    db.lock("legacy-social:migration");
    std::map<std::string, Json> certificates;
    auto rows = db.query("SELECT id,record FROM browser_accounts");
    for (int i = 0; i < rows.size(); ++i) {
        auto record = rows.json(i, 1);
        auto identity = legacy_identity(record.at("certificate"), text(record, "issuer_signature", 1024));
        require(identity.first == rows.at(i, 0), "invalid", "Migrated identity mismatch");
        certificates.emplace(identity.first, record.at("certificate"));
        db.query("INSERT INTO identities(id,public_key,username) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING",
                 {identity.first, identity.second, text(record.at("certificate"), "username", 32)});
        auto existing = db.query("SELECT public_key FROM identities WHERE id=$1", {identity.first});
        require(Json::parse(existing.at(0, 0)) == Json::parse(identity.second), "conflict",
                "Routing identity key mismatch", 409);
    }
    using Edge = std::pair<std::string, std::string>;
    std::map<Edge, Json> latest;
    std::map<Edge, std::string> identifiers;
    auto remember = [&](const Json &event) {
        auto event_key = Edge{text(event.at("grant"), "a", 80), text(event.at("action"), "id", 32)};
        auto digest = sha256(event.dump(-1, ' ', true));
        auto [known, inserted] = identifiers.emplace(event_key, digest);
        require(inserted || known->second == digest, "conflict", "Historical event ID reused", 409);
        auto key = Edge{text(event.at("grant"), "a", 80), text(event.at("action"), "target", 80)};
        auto it = latest.find(key);
        auto order = [](const Json &e) {
            return std::pair<double, std::string>{e.at("action").at("at").get<double>(),
                                                  text(e.at("action"), "id", 32)};
        };
        if (it == latest.end() || order(event) > order(it->second))
            latest[key] = event;
    };
    auto saved = db.query("SELECT body FROM legacy_social_import");
    for (int i = 0; i < saved.size(); ++i)
        remember(saved.json(i));
    std::size_t added = 0;
    for (const auto &event : events) {
        require(event.is_object() && event.size() == 4, "invalid", "Invalid signed social event");
        const auto &grant = event.at("grant"), &action = event.at("action");
        auto actor = text(grant, "a", 80), target = text(action, "target", 80), op = text(action, "op", 16);
        require(actor != target && certificates.contains(actor) && certificates.contains(target), "invalid",
                "Missing social identity");
        require(op == "request" || op == "accept" || op == "remove", "invalid",
                "Only durable relationship events may be imported");
        require(action.size() == (op == "accept" ? 5u : 4u) && action.at("at").is_number(), "invalid",
                "Invalid relationship fields");
        auto at = action.at("at").get<double>();
        auto kind = text(grant, "p", 64);
        auto expiry = integer(grant, "e", 0, INT64_MAX);
        auto begin =
            kind == "buggcraft-launcher-device-v1" ? integer(grant, "b", 0, INT64_MAX) : expiry - 7 * 86400;
        require((kind == "buggcraft-launcher-device-v1" || kind == "buggcraft-account-login-v2") &&
                    begin >= 0 && expiry >= begin && expiry - begin <= 180 * 86400 &&
                    text(grant, "i", 32) == text(certificates.at(actor), "home", 32) && at >= double(begin - 60) &&
                    at <= double(expiry) && at <= double(unix_seconds() + 5),
                "invalid", "Invalid historical grant window");
        require(verify_account_proof(certificates.at(actor).at("public_key").dump(),
                                     grant.dump(-1, ' ', true), text(event, "proof", 256)) &&
                    verify_account_proof(grant.at("d").dump(), action.dump(-1, ' ', true),
                                         text(event, "signature", 256)),
                "unauthorized", "Invalid historical social signature", 401);
        auto event_id = text(action, "id", 32);
        require(event_id.size() == 32 && unhex(event_id).size() == 16, "invalid", "Invalid event ID");
        if (op == "accept")
            require(text(action, "ref", 32).size() == 32, "invalid", "Invalid acceptance reference");
        auto digest = sha256(event.dump(-1, ' ', true));
        auto inserted = db.query("INSERT INTO legacy_social_import(digest,body) VALUES($1,$2::jsonb) ON "
                                 "CONFLICT DO NOTHING RETURNING digest",
                                 {digest, event.dump()});
        added += std::size_t(inserted.size());
        remember(event);
    }
    std::set<Edge> pairs;
    for (const auto &[edge, event] : latest) {
        (void)event;
        pairs.insert(std::minmax(edge.first, edge.second));
    }
    std::size_t accepted = 0, pending = 0;
    for (const auto &[low, high] : pairs) {
        auto first = latest.find({low, high}), second = latest.find({high, low});
        const Json *a = first == latest.end() ? nullptr : &first->second.at("action");
        const Json *b = second == latest.end() ? nullptr : &second->second.at("action");
        auto accepts = [](const Json *x, const Json *y) {
            return x && y && x->at("op") == "accept" && y->at("op") == "request" &&
                   x->at("ref") == y->at("id") && x->at("at").get<double>() >= y->at("at").get<double>();
        };
        std::string state, requester;
        if (accepts(a, b)) {
            state = "accepted";
            requester = high;
        } else if (accepts(b, a)) {
            state = "accepted";
            requester = low;
        } else if ((a && a->at("op") == "remove") || (b && b->at("op") == "remove")) {
            state = "rejected";
            requester = low;
        } else if (a && a->at("op") == "request") {
            state = "pending";
            requester = low;
        } else if (b && b->at("op") == "request") {
            state = "pending";
            requester = high;
        } else
            continue;
        // Existing native relationships win; repeated imports never undo a
        // player's later native acceptance/removal.
        db.query("INSERT INTO friendships(low_id,high_id,requested_by,state) VALUES($1,$2,$3,$4) ON CONFLICT "
                 "DO NOTHING",
                 {low, high, requester, state});
        accepted += state == "accepted";
        pending += state == "pending";
    }
    transaction.commit();
    return {{"events_added", added}, {"accepted_pairs", accepted}, {"pending_pairs", pending}};
}
} // namespace control
