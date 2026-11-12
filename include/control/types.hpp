#pragma once
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

namespace control {
using Json = nlohmann::json;
// Domain errors contain public classifications only; database/TLS details never leave the service.
struct Error : std::runtime_error {
    int status;
    std::string code;
    Error(int status_, std::string code_, std::string message)
        : std::runtime_error(std::move(message)), status(status_), code(std::move(code_)) {}
};
void require(bool condition, std::string_view code, std::string_view message, int status = 400);
Json parse_json(std::string_view input, std::size_t limit = 65536);
void select_json_backend(std::string_view name);
std::string json_backend();
std::string text(const Json &value, std::string_view key, std::size_t max = 256);
std::int64_t integer(const Json &value, std::string_view key, std::int64_t low, std::int64_t high);
std::string read_file(const std::string &path, std::size_t max = 1048576);
std::string read_secret(const std::string &path, std::size_t max = 16384);
std::int64_t unix_seconds();
} // namespace control
