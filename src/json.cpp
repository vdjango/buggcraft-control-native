#include "control/types.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <simdjson.h>

namespace control {
void require(bool condition, std::string_view code, std::string_view message, int status) {
    if (!condition)
        throw Error(status, std::string(code), std::string(message));
}
namespace {
Json convert(simdjson::dom::element element, unsigned depth) {
    require(depth <= 24, "invalid", "JSON nesting exceeds limit");
    switch (element.type()) {
    case simdjson::dom::element_type::OBJECT: {
        Json result = Json::object();
        for (auto field : simdjson::dom::object(element)) {
            std::string key(field.key);
            require(!result.contains(key), "invalid", "Duplicate JSON key");
            result[key] = convert(field.value, depth + 1);
        }
        return result;
    }
    case simdjson::dom::element_type::ARRAY: {
        Json result = Json::array();
        for (auto item : simdjson::dom::array(element))
            result.push_back(convert(item, depth + 1));
        return result;
    }
    case simdjson::dom::element_type::STRING:
        return std::string(std::string_view(element));
    case simdjson::dom::element_type::INT64:
        return std::int64_t(element);
    case simdjson::dom::element_type::UINT64:
        return std::uint64_t(element);
    case simdjson::dom::element_type::DOUBLE:
        return double(element);
    case simdjson::dom::element_type::BOOL:
        return bool(element);
    case simdjson::dom::element_type::NULL_VALUE:
        return nullptr;
    }
    throw Error(400, "invalid", "Unsupported JSON value");
}
} // namespace
Json parse_json(std::string_view input, std::size_t limit) {
    require(limit <= 16777216 && input.size() <= limit, "too_large", "Request exceeds limit", 413);
    thread_local simdjson::dom::parser parser;
    simdjson::padded_string padded(input);
    simdjson::dom::element element;
    auto error = parser.parse(padded).get(element);
    require(!error, "invalid", "Invalid JSON");
    return convert(element, 0);
}
void select_json_backend(std::string_view name) {
    if (name == "auto")
        return;
    const auto *implementation = simdjson::get_available_implementations()[std::string(name)];
    require(implementation && implementation->supported_by_runtime_system(), "config",
            "Unsupported JSON backend");
    simdjson::get_active_implementation() = implementation;
}
std::string json_backend() {
    // Trigger lazy runtime CPU/OS dispatch before reporting the backend.
    (void)parse_json("{}");
    return simdjson::get_active_implementation()->name();
}
std::string text(const Json &value, std::string_view key, std::size_t max) {
    auto found = value.find(std::string(key));
    require(found != value.end() && found->is_string(), "invalid",
            "Missing or non-string field: " + std::string(key));
    auto result = found->get<std::string>();
    require(!result.empty() && result.size() <= max && result.find('\0') == std::string::npos, "invalid",
            "Invalid field length: " + std::string(key));
    return result;
}
std::int64_t integer(const Json &value, std::string_view key, std::int64_t low, std::int64_t high) {
    auto found = value.find(std::string(key));
    require(found != value.end() && found->is_number_integer(), "invalid",
            "Missing integer: " + std::string(key));
    require(!found->is_number_unsigned() || found->get<std::uint64_t>() <= std::uint64_t(INT64_MAX),
            "invalid", "Integer overflow");
    auto result = found->get<std::int64_t>();
    require(result >= low && result <= high, "invalid", "Integer outside range: " + std::string(key));
    return result;
}
std::string read_file(const std::string &path, std::size_t max) {
    std::ifstream stream(path, std::ios::binary);
    require(bool(stream), "config", "Unable to open configured file", 500);
    std::string result((std::istreambuf_iterator<char>(stream)), {});
    require(result.size() <= max && !result.empty(), "config", "Configured file empty or too large", 500);
    return result;
}
std::string read_secret(const std::string &path, std::size_t max) {
#ifndef _WIN32
    auto permissions = std::filesystem::status(path).permissions();
    using P = std::filesystem::perms;
    require((permissions & (P::group_all | P::others_all)) == P::none, "config",
            "Secret file must not be accessible to group/others", 500);
#endif
    return read_file(path, max);
}
std::int64_t unix_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace control
