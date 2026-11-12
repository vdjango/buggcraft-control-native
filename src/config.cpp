#include "control/config.hpp"
#include <filesystem>
#include <set>

namespace control {
Config Config::load(const std::string &path) {
    auto value = parse_json(read_file(path, 65536));
    require(value.is_object(), "config", "Configuration must be an object");
    const std::set<std::string> known = {"listen",
                                         "port",
                                         "tls_certificate",
                                         "tls_key",
                                         "signing_key",
                                         "database_file",
                                         "admin_token_file",
                                         "schema_file",
                                         "public_enrollment_credential_file",
                                         "browser",
                                         "audience",
                                         "json_implementation",
                                         "io_threads",
                                         "workers",
                                         "queue_limit",
                                         "max_connections",
                                         "grant_seconds",
                                         "node_lease_seconds",
                                         "player_lease_seconds",
                                         "reservation_seconds",
                                         "heartbeat_limit",
                                         "candidate_limit",
                                         "allow_loopback_nodes",
                                         "allowed_pools",
                                         "node_slot_limit",
                                         "node_bandwidth_limit",
                                         "region_routes"};
    for (auto it = value.begin(); it != value.end(); ++it)
        require(known.contains(it.key()), "config", "Unknown configuration key: " + it.key());
    Config config;
    auto base = std::filesystem::absolute(path).parent_path();
    if(value.contains("browser"))config.browser=BrowserConfig::load(value.at("browser"),base.string());
    auto file = [&](const char *name) {
        return (base / text(value, name, 4096)).lexically_normal().string();
    };
    config.tls_certificate = file("tls_certificate");
    config.tls_key = file("tls_key");
    config.signing_key = file("signing_key");
    config.database_file = file("database_file");
    config.admin_token_file = file("admin_token_file");
    config.schema_file = file("schema_file");
    if (value.contains("public_enrollment_credential_file"))
        config.public_enrollment_credential_file = file("public_enrollment_credential_file");
    auto number = [&](const char *name, int fallback, int low, int high) {
        return int(value.contains(name) ? integer(value, name, low, high) : fallback);
    };
    config.listen = value.value("listen", config.listen);
    config.audience = value.value("audience", config.audience);
    require(!config.audience.empty() && config.audience.size() <= 128, "config", "Invalid audience");
    config.port = static_cast<unsigned short>(number("port", 8443, 1, 65535));
    config.io_threads = unsigned(number("io_threads", 2, 1, 64));
    config.workers = unsigned(number("workers", 4, 1, 64));
    config.queue_limit = unsigned(number("queue_limit", 128, 1, 65536));
    config.max_connections = unsigned(number("max_connections", 512, 1, 100000));
    config.grant_seconds = number("grant_seconds", 900, 60, 3600);
    config.node_lease_seconds = number("node_lease_seconds", 20, 5, 120);
    config.player_lease_seconds = number("player_lease_seconds", 30, 5, 120);
    config.reservation_seconds = number("reservation_seconds", 30, 5, 120);
    config.heartbeat_limit = number("heartbeat_limit", 120, 10, 10000);
    config.candidate_limit = unsigned(number("candidate_limit", 8, 1, 8));
    config.node_slot_limit = unsigned(number("node_slot_limit", 2048, 1, 100000));
    config.node_bandwidth_limit = value.contains("node_bandwidth_limit")
                                      ? integer(value, "node_bandwidth_limit", 1, 1000000000000LL)
                                      : 1000000000;
    config.allowed_pools = value.value("allowed_pools", config.allowed_pools);
    config.region_routes = value.value("region_routes", config.region_routes);
    require(config.region_routes.is_object() && config.region_routes.size() <= 256, "config",
            "Invalid region routes");
    for (auto it = config.region_routes.begin(); it != config.region_routes.end(); ++it) {
        require(it.key().size() <= 64 && it.value().is_array() && it.value().size() <= 3, "config",
                "Invalid region fallback list");
        for (const auto &region : it.value())
            require(region.is_string() && !region.get<std::string>().empty() &&
                        region.get<std::string>().size() <= 64,
                    "config", "Invalid fallback region");
    }
    require(config.allowed_pools.is_array() && !config.allowed_pools.empty() &&
                config.allowed_pools.size() <= 8,
            "config", "Expected 1-8 allowed pools");
    for (const auto &pool : config.allowed_pools)
        require(pool.is_string() && !pool.get<std::string>().empty() && pool.get<std::string>().size() <= 64,
                "config", "Invalid pool name");
    config.json_implementation = value.value("json_implementation", "auto");
    config.allow_loopback_nodes = value.value("allow_loopback_nodes", false);
    return config;
}
} // namespace control
