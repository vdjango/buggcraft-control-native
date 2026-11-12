#pragma once
#include "types.hpp"
#include <map>

namespace control {
// Owned values only. Handlers execute on bounded database workers, never I/O.
struct BrowserRequest {
    std::string method, target, origin, cookie, csrf, content_type, peer, user_agent;
    Json body = Json::object();
};
struct BrowserReply {
    int status = 200;
    std::string body, content_type = "application/json", cookie, location;
    BrowserReply() = default;
    BrowserReply(int code, std::string payload) : status(code), body(std::move(payload)) {}
};
struct BrowserConfig {
    std::string origin, assets, issuer_key, issuer_public, audience_key_file;
    std::string name = "Bugg", region = "cn-east", operator_name = "unknown";
    std::string smtp_file;
    std::string client_ca;
    bool registration_open = false;
    bool trust_loopback_proxy = false;
    static BrowserConfig load(const Json &, const std::string &base);
};
std::string base64url(std::string_view);
std::string decode_base64(std::string);
std::string ssh_signature(const std::string &signature_hex);
std::string ssh_public_key(const std::string &key_hex);
std::string hmac_sha256(std::string_view key, std::string_view message);
// libcurl owns SMTP/TLS; validated inputs cannot inject headers.
void send_browser_mail(const Json &settings, const std::string &mailbox, const std::string &code);
} // namespace control
