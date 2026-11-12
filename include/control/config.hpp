#pragma once
#include "types.hpp"
#include "browser.hpp"
#include <optional>

namespace control {
struct Config {
    std::string listen = "127.0.0.1";
    unsigned short port = 8443;
    std::string tls_certificate, tls_key, signing_key, database_file, admin_token_file, schema_file;
    std::string public_enrollment_credential_file;
    std::optional<BrowserConfig> browser;
    std::string audience = "buggcraft-control-v1";
    std::string json_implementation = "auto";
    unsigned io_threads = 2, workers = 4, queue_limit = 128, max_connections = 512;
    int grant_seconds = 900, node_lease_seconds = 20, player_lease_seconds = 30;
    int reservation_seconds = 30, heartbeat_limit = 120;
    unsigned candidate_limit = 8;
    unsigned node_slot_limit = 2048;
    std::int64_t node_bandwidth_limit = 1000000000;
    Json allowed_pools = Json::array({"community"});
    Json region_routes = Json::object();
    bool allow_loopback_nodes = false;
    static Config load(const std::string &path);
};
} // namespace control
