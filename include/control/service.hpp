#pragma once
#include "config.hpp"
#include "crypto.hpp"
#include "database.hpp"
#include <atomic>

namespace control {
struct Actor {
    std::string kind, id, device, epoch;
    int64_t expires = INT64_MAX;
};
struct Reply {
    int status = 200;
    Json body;
};
bool probe_node(const std::string &endpoint, const std::string &proof_endpoint, const std::string &public_key,
                bool allow_loopback);
class Service {
    void record_activity(Database &, const std::string &account, const std::string &kind, int lease);
    void record_companions(Database &, const std::string &account, const std::string &room,
                           const std::string &epoch);
    Json activity(Database &, const std::string &account);
    Config config_;
    Signer signer_;
    std::string admin_digest_;
    std::unique_ptr<Signer> browser_signer_;
    std::string browser_audience_;
    Json browser_smtp_;
    Actor authenticate(Database &, std::string_view token);
    Json enrollment(Database &, const std::string &, const Json &);
    Json node(Database &, const std::string &, const Json &, const Actor &);
    Json placement(Database &, const std::string &, const Json &, const Actor &);
    Json placement_lease(Database &, const std::string &, const Json &, const Actor &,
                         bool active_only = false);
    Json presence(Database &, const std::string &, const Json &, const Actor &);
    Json social(Database &, const std::string &, const Json &, const Actor &);
    Json admin(Database &, const std::string &, const Json &);
    void actor_kind(const Actor &, std::string_view kind) const;
    void idempotency_lock(Database &, std::string_view actor, std::string_view key) const;
    Json grant(const Actor &) const;
    Json browser_api(Database &, const BrowserRequest &, const std::string &path,
                     const std::map<std::string, std::string> &query, const Json &proofs, BrowserReply &);

  public:
    explicit Service(Config config);
    Reply dispatch(Database &, const std::string &path, std::string_view bearer, const Json &body);
    BrowserReply browser(Database &, const BrowserRequest &);
    Json import_browser(Database &, const Json &snapshot);
    Json import_social(Database &, const Json &events);
    void maintain(Database &);
    const Config &config() const {
        return config_;
    }
    const Signer &signer() const {
        return signer_;
    }
};
} // namespace control
