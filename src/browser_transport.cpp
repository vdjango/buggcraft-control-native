#include "control/browser.hpp"
#include "control/crypto.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <curl/curl.h>
#include <filesystem>
#include <iostream>
#include <openssl/hmac.h>
#include <regex>

namespace control {
BrowserConfig BrowserConfig::load(const Json &value, const std::string &base) {
    require(value.is_object(), "config", "Browser configuration must be an object");
    BrowserConfig result;
    auto file = [&](const char *key) {
        return (std::filesystem::path(base) / text(value, key, 4096)).lexically_normal().string();
    };
    result.origin = text(value, "origin", 256);
    require(std::regex_match(result.origin, std::regex(R"(https://[A-Za-z0-9.:-]+)")), "config",
            "Invalid browser origin");
    result.assets = file("assets");
    result.issuer_key = file("issuer_key");
    result.audience_key_file = file("audience_key_file");
    result.issuer_public = text(value, "issuer_public", 256);
    result.registration_open = value.value("registration_open", false);
    result.trust_loopback_proxy = value.value("trust_loopback_proxy", false);
    result.name = value.value("name", result.name);
    result.region = value.value("region", result.region);
    result.operator_name = value.value("operator", result.operator_name);
    if (value.contains("smtp_file"))
        result.smtp_file = file("smtp_file");
    if (value.contains("client_ca_file"))
        result.client_ca = read_file(file("client_ca_file"), 65536);
    return result;
}
std::string base64url(std::string_view bytes) {
    require(bytes.size() <= 65536, "invalid", "Encoding limit exceeded");
    std::string result(4 * ((bytes.size() + 2) / 3), '\0');
    if (!bytes.empty())
        EVP_EncodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                        reinterpret_cast<const unsigned char *>(bytes.data()), int(bytes.size()));
    while (!result.empty() && result.back() == '=')
        result.pop_back();
    for (auto &c : result) {
        if (c == '+')
            c = '-';
        if (c == '/')
            c = '_';
    }
    return result;
}
namespace {
std::string ssh_field(std::string_view value) {
    std::string result(4, '\0');
    auto size = value.size();
    for (int i = 3; i >= 0; --i) {
        result[std::size_t(i)] = char(size & 255);
        size >>= 8;
    }
    return result + std::string(value);
}
} // namespace
std::string ssh_signature(const std::string &signature_hex) {
    return base64url(ssh_field("ssh-ed25519") + ssh_field(unhex(signature_hex)));
}
std::string ssh_public_key(const std::string &key_hex) {
    auto encoded = base64url(ssh_field("ssh-ed25519") + ssh_field(unhex(key_hex)));
    std::replace(encoded.begin(), encoded.end(), '-', '+');
    std::replace(encoded.begin(), encoded.end(), '_', '/');
    encoded.append((4 - encoded.size() % 4) % 4, '=');
    return "ssh-ed25519 " + encoded;
}
std::string hmac_sha256(std::string_view key, std::string_view message) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> output{};
    unsigned size = 0;
    require(HMAC(EVP_sha256(), key.data(), int(key.size()),
                 reinterpret_cast<const unsigned char *>(message.data()), message.size(), output.data(),
                 &size) != nullptr,
            "internal", "Authentication digest failed", 500);
    return hex(std::string_view(reinterpret_cast<char *>(output.data()), size));
}
void send_browser_mail(const Json &settings, const std::string &mailbox, const std::string &code) {
    static std::atomic_uint inflight{0};
    const auto previous = inflight.fetch_add(1);
    struct Delivery {
        std::atomic_uint &count;
        ~Delivery() {
            --count;
        }
    } delivery{inflight};
    require(previous < 2, "mail_busy", "发信服务繁忙，请稍后重试。", 503);
    static const int initialized = []() { return int(curl_global_init(CURL_GLOBAL_DEFAULT)); }();
    require(initialized == 0, "unavailable", "邮件服务暂不可用。", 503);
    auto host = text(settings, "host", 253), user = text(settings, "username", 254),
         password = text(settings, "password", 512);
    auto safe_mail = [](const std::string &value) {
        return std::regex_match(
            value, std::regex(R"([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"));
    };
    require(safe_mail(mailbox) && safe_mail(user) && std::regex_match(host, std::regex("[A-Za-z0-9.-]+")),
            "invalid", "邮箱地址无效。");
    int port = int(integer(settings, "port", 1, 65535));
    const bool implicit_tls = settings.value("implicit_tls", port != 587);
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    require(bool(curl), "unavailable", "邮件服务暂不可用。", 503);
    std::string payload = "From: Bugg <" + user + ">\r\nTo: <" + mailbox +
                          ">\r\nSubject: Bugg verification code\r\nContent-Type: text/plain; "
                          "charset=UTF-8\r\n\r\nBugg verification code: " +
                          code +
                          "\r\nExpires in 10 minutes. If you did not request it, ignore this message.\r\n";
    struct Upload {
        std::string *text;
        std::size_t position = 0;
    } upload{&payload};
    auto reader = +[](char *buffer, std::size_t size, std::size_t count, void *opaque) -> std::size_t {
        auto &data = *static_cast<Upload *>(opaque);
        auto take = std::min(size * count, data.text->size() - data.position);
        std::copy_n(data.text->data() + data.position, take, buffer);
        data.position += take;
        return take;
    };
    auto destination = "<" + mailbox + ">", sender = "<" + user + ">";
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> recipients(
        curl_slist_append(nullptr, destination.c_str()), curl_slist_free_all);
    auto url = std::string(implicit_tls ? "smtps://" : "smtp://") + host + ":" + std::to_string(port);
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_USERNAME, user.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PASSWORD, password.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_USE_SSL, long(CURLUSESSL_ALL));
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    const auto ca = settings.value("ca_file", std::string());
    if (!ca.empty())
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, ca.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_MAIL_FROM, sender.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_MAIL_RCPT, recipients.get());
    curl_easy_setopt(curl.get(), CURLOPT_READFUNCTION, reader);
    curl_easy_setopt(curl.get(), CURLOPT_READDATA, &upload);
    curl_easy_setopt(curl.get(), CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 12L);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    const auto status = curl_easy_perform(curl.get());
    if (status != CURLE_OK)
        std::cerr << "smtp: deferred transport code=" << int(status) << '\n';
    require(status == CURLE_OK, "mail_unavailable", "邮件暂未发出，请稍后重试。", 503);
}
} // namespace control
