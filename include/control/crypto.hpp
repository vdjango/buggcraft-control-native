#pragma once
#include "types.hpp"
#include <memory>
#include <openssl/evp.h>

namespace control {
std::string hex(std::string_view bytes);
std::string unhex(std::string_view input);
std::string sha256(std::string_view input);
std::string random_id();
bool secure_equal(std::string_view a, std::string_view b);
std::string decode_base64(std::string input);
bool verify_ed25519(std::string_view public_key_hex, std::string_view message,
                    std::string_view signature_hex);
bool verify_account_proof(std::string_view public_key, std::string_view message, std::string_view signature);
// Validate only the signed public certificate; encrypted user vaults are never imported here.
std::pair<std::string, std::string> legacy_identity(const Json &certificate,
                                                    std::string_view issuer_signature);
struct Delegation {
    std::string account, public_key, device, key, digest, username;
    int64_t expires;
};
Delegation verify_delegation(const Json &body, bool require_current = true);
class Signer {
    std::shared_ptr<EVP_PKEY> key_;

  public:
    explicit Signer(const std::string &pem_file);
    explicit Signer(std::shared_ptr<EVP_PKEY> key);
    std::string public_key() const;
    std::string sign(std::string_view message) const;
    std::string token(const Json &claims) const;
    Json verify(std::string_view token, std::string_view audience) const;
};
} // namespace control
