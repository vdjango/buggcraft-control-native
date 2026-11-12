#include "control/crypto.hpp"
#include <array>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <regex>

namespace control {
std::string hex(std::string_view bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        auto c = static_cast<unsigned char>(bytes[i]);
        output[2 * i] = digits[c >> 4];
        output[2 * i + 1] = digits[c & 15];
    }
    return output;
}
std::string unhex(std::string_view input) {
    require(input.size() % 2 == 0 && input.size() <= 16384, "invalid", "Invalid hex length");
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9')
            return unsigned(c - '0');
        if (c >= 'a' && c <= 'f')
            return unsigned(c - 'a' + 10);
        throw Error(400, "invalid", "Expected lowercase hex");
    };
    std::string result(input.size() / 2, '\0');
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = char((nibble(input[2 * i]) << 4) | nibble(input[2 * i + 1]));
    return result;
}
std::string sha256(std::string_view input) {
    std::array<unsigned char, 32> output{};
    unsigned size = 0;
    require(EVP_Digest(input.data(), input.size(), output.data(), &size, EVP_sha256(), nullptr) == 1,
            "internal", "Digest failed", 500);
    return hex(std::string_view(reinterpret_cast<char *>(output.data()), size));
}
std::string random_id() {
    std::array<unsigned char, 24> output{};
    require(RAND_bytes(output.data(), int(output.size())) == 1, "internal", "Random generation failed", 500);
    return hex(std::string_view(reinterpret_cast<char *>(output.data()), output.size()));
}
bool secure_equal(std::string_view a, std::string_view b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
bool verify_ed25519(std::string_view public_key_hex, std::string_view message,
                    std::string_view signature_hex) {
    auto key = unhex(public_key_hex), signature = unhex(signature_hex);
    if (key.size() != 32 || signature.size() != 64)
        return false;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                    reinterpret_cast<const unsigned char *>(key.data()), key.size()),
        EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return pkey && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) == 1 &&
           EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char *>(signature.data()),
                            signature.size(), reinterpret_cast<const unsigned char *>(message.data()),
                            message.size()) == 1;
}
std::string decode_base64(std::string input) {
    require(input.size() <= 8192, "invalid", "Base64 exceeds limit");
    for (auto &c : input) {
        if (c == '-')
            c = '+';
        if (c == '_')
            c = '/';
    }
    while (input.size() % 4)
        input.push_back('=');
    std::string output(input.size(), '\0');
    auto size = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                                reinterpret_cast<const unsigned char *>(input.data()), int(input.size()));
    require(size >= 0, "invalid", "Invalid base64");
    if (!input.empty() && input.back() == '=')
        --size;
    if (input.size() > 1 && input[input.size() - 2] == '=')
        --size;
    require(size >= 0, "invalid", "Invalid base64 padding");
    output.resize(std::size_t(size));
    return output;
}
namespace {
std::string ssh_string(std::string_view &blob) {
    require(blob.size() >= 4, "invalid", "Invalid SSH field");
    std::uint32_t size = 0;
    for (int i = 0; i < 4; ++i)
        size = (size << 8) | static_cast<unsigned char>(blob[std::size_t(i)]);
    blob.remove_prefix(4);
    require(size <= blob.size(), "invalid", "Invalid SSH field length");
    std::string result(blob.substr(0, size));
    blob.remove_prefix(size);
    return result;
}
std::shared_ptr<EVP_PKEY> p256_key(const Json &jwk) {
    require(jwk.size() == 4 && jwk.value("kty", "") == "EC" && jwk.value("crv", "") == "P-256", "invalid",
            "Unsupported account key");
    auto x = decode_base64(text(jwk, "x", 64)), y = decode_base64(text(jwk, "y", 64));
    require(x.size() == 32 && y.size() == 32, "invalid", "Invalid account coordinates");
    auto point = std::string(1, '\4') + x + y;
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> builder(OSSL_PARAM_BLD_new(),
                                                                            OSSL_PARAM_BLD_free);
    require(builder &&
                OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) &&
                OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(),
                                                 point.size()),
            "invalid", "Invalid account key");
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(builder.get()),
                                                                   OSSL_PARAM_free);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY *key = nullptr;
    require(context && EVP_PKEY_fromdata_init(context.get()) == 1 &&
                EVP_PKEY_fromdata(context.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) == 1,
            "invalid", "Invalid account point");
    return {key, EVP_PKEY_free};
}
} // namespace
bool verify_account_proof(std::string_view public_key, std::string_view message, std::string_view signature) {
    if (!public_key.starts_with('{'))
        return verify_ed25519(public_key, message, signature);
    auto key = p256_key(parse_json(public_key));
    auto raw = decode_base64(std::string(signature));
    if (raw.size() != 64)
        return false;
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
    auto *r = BN_bin2bn(reinterpret_cast<const unsigned char *>(raw.data()), 32, nullptr);
    auto *s = BN_bin2bn(reinterpret_cast<const unsigned char *>(raw.data() + 32), 32, nullptr);
    require(sig && r && s, "internal", "Signature allocation failed", 500);
    ECDSA_SIG_set0(sig.get(), r, s);
    auto size = i2d_ECDSA_SIG(sig.get(), nullptr);
    std::string der(std::size_t(size), '\0');
    auto *pointer = reinterpret_cast<unsigned char *>(der.data());
    i2d_ECDSA_SIG(sig.get(), &pointer);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return context && EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) == 1 &&
           EVP_DigestVerify(context.get(), reinterpret_cast<unsigned char *>(der.data()), der.size(),
                            reinterpret_cast<const unsigned char *>(message.data()), message.size()) == 1;
}
std::pair<std::string, std::string> legacy_identity(const Json &cert, std::string_view issuer_signature) {
    require(cert.is_object() && cert.size() == 6 && cert.contains("public_key") && cert.contains("created") &&
                cert["created"].is_number(),
            "invalid", "Invalid public identity certificate");
    auto uid = text(cert, "uid", 32), home = text(cert, "home", 32), name = text(cert, "username", 32);
    static const std::regex id_pattern("[0-9a-f]{32}"), name_pattern("[A-Za-z0-9_-]{3,32}");
    require(std::regex_match(uid, id_pattern) && std::regex_match(home, id_pattern) &&
                std::regex_match(name, name_pattern),
            "invalid", "Invalid public identity fields");
    auto home_key = text(cert, "home_key", 4096);
    auto space = home_key.find(' '), next = home_key.find_first_of(" \t\r\n", space + 1);
    require(space != std::string::npos && home_key.substr(0, space) == "ssh-ed25519", "incompatible",
            "Issuer key must be ssh-ed25519");
    auto encoded = home_key.substr(space + 1, next == std::string::npos ? next : next - space - 1);
    auto normalized = std::string("ssh-ed25519 ") + encoded;
    require(sha256(normalized).substr(0, 32) == home, "invalid", "Issuer identity does not match key");
    auto key_blob = decode_base64(encoded);
    std::string_view key_view(key_blob);
    require(ssh_string(key_view) == "ssh-ed25519", "invalid", "Unsupported issuer key");
    auto key = ssh_string(key_view);
    require(key_view.empty() && key.size() == 32, "invalid", "Invalid issuer key");
    auto sig_blob = decode_base64(std::string(issuer_signature));
    std::string_view sig_view(sig_blob);
    require(ssh_string(sig_view) == "ssh-ed25519", "invalid", "Unsupported issuer signature");
    auto sig = ssh_string(sig_view);
    require(sig_view.empty() && sig.size() == 64, "invalid", "Invalid issuer signature");
    // Existing certificate JSON is sorted ASCII. No private vault or replica authorization is inferred.
    auto canonical = cert.dump(-1, ' ', true);
    require(verify_ed25519(hex(key), canonical, hex(sig)), "unauthorized",
            "Invalid issuer certificate signature", 401);
    (void)p256_key(cert["public_key"]);
    return {uid + "." + home, cert["public_key"].dump()};
}
Delegation verify_delegation(const Json &body, bool require_current) {
    const auto &certificate = body.at("certificate");
    auto identity = legacy_identity(certificate, text(body, "issuer_signature", 1024));
    const auto &delegation = body.at("device_grant");
    auto device = text(body, "device_id", 64);
    require(delegation.is_object() && delegation.value("a", "") == identity.first &&
                delegation.value("p", "") == "buggcraft-launcher-device-v1" &&
                delegation.value("r", "") == device && delegation.contains("d"),
            "unauthorized", "Invalid device delegation", 401);
    auto expiry = integer(delegation, "e", 0, INT64_MAX);
    auto issued = integer(delegation, "b", 0, INT64_MAX);
    require((!require_current || expiry > unix_seconds()) && issued <= unix_seconds() + 5 && expiry > issued &&
                expiry - issued <= 180 * 86400,
            "unauthorized", "Expired device delegation", 401);
    auto canonical = delegation.dump(-1, ' ', true);
    require(verify_account_proof(identity.second, canonical, text(body, "delegation_signature", 256)),
            "unauthorized", "Invalid device delegation signature", 401);
    auto key = delegation["d"].dump();
    (void)verify_account_proof(key, "validate-key", "AA");
    return {
        identity.first, identity.second, device, key, sha256(canonical), text(certificate, "username", 32),
        expiry};
}
Signer::Signer(const std::string &pem_file) {
    auto pem = read_secret(pem_file, 16384);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), int(pem.size())), BIO_free);
    key_ = {PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
    require(key_ && EVP_PKEY_is_a(key_.get(), "ED25519"), "config", "Signing key must be Ed25519", 500);
}
Signer::Signer(std::shared_ptr<EVP_PKEY> key) : key_(std::move(key)) {
    require(key_ && EVP_PKEY_is_a(key_.get(), "ED25519"), "config", "Invalid signing key", 500);
}
std::string Signer::public_key() const {
    std::array<unsigned char, 32> output{};
    std::size_t size = output.size();
    require(EVP_PKEY_get_raw_public_key(key_.get(), output.data(), &size) == 1, "internal",
            "Public key failed", 500);
    return hex(std::string_view(reinterpret_cast<char *>(output.data()), size));
}
std::string Signer::sign(std::string_view message) const {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::array<unsigned char, 64> signature{};
    std::size_t size = signature.size();
    require(ctx && EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key_.get()) == 1 &&
                EVP_DigestSign(ctx.get(), signature.data(), &size,
                               reinterpret_cast<const unsigned char *>(message.data()), message.size()) == 1,
            "internal", "Signing failed", 500);
    return hex(std::string_view(reinterpret_cast<char *>(signature.data()), size));
}
std::string Signer::token(const Json &claims) const {
    auto payload = hex(claims.dump());
    return payload + "." + sign(payload);
}
Json Signer::verify(std::string_view encoded, std::string_view audience) const {
    require(encoded.size() <= 8192, "unauthorized", "Invalid authorization", 401);
    auto dot = encoded.find('.');
    require(dot != std::string_view::npos &&
                verify_ed25519(public_key(), encoded.substr(0, dot), encoded.substr(dot + 1)),
            "unauthorized", "Invalid authorization", 401);
    auto claims = parse_json(unhex(encoded.substr(0, dot)));
    require(claims.is_object() && claims.value("aud", "") == audience &&
                integer(claims, "exp", 0, INT64_MAX) > unix_seconds(),
            "expired", "Authorization expired or wrong audience", 401);
    return claims;
}
} // namespace control
