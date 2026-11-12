#include "control/crypto.hpp"
#include <iostream>

using namespace control;
int main() {
    unsigned checks = 0;
    auto check = [&](bool value) {
        ++checks;
        if (!value)
            throw std::runtime_error("Unit assertion failed");
    };
    auto rejected = [&](auto action) {
        bool failed = false;
        try {
            action();
        } catch (const Error &) {
            failed = true;
        }
        check(failed);
    };
    try {
        check(sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check(unhex(hex(std::string("a\0z", 3))) == std::string("a\0z", 3));
        rejected([] { unhex("abX0"); });
        rejected([] { unhex("abc"); });
        check(parse_json(R"({"a":[1,true,null,"中"]})")["a"].size() == 4);
        rejected([] { parse_json(R"({"a":1,"a":2})"); });
        rejected([] { parse_json("{bad}"); });
        rejected([] { parse_json(std::string(65537, ' ')); });
        rejected([] { integer(Json({{"x", 18446744073709551615ULL}}), "x", 0, INT64_MAX); });
        rejected([] { text(Json({{"x", ""}}), "x"); });
        auto key = std::shared_ptr<EVP_PKEY>(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
        Signer signer(key);
        auto signature = signer.sign("proof");
        check(verify_ed25519(signer.public_key(), "proof", signature));
        check(!verify_ed25519(signer.public_key(), "changed", signature));
        auto token = signer.token({{"aud", "unit"}, {"exp", unix_seconds() + 60}, {"sub", "u"}});
        check(signer.verify(token, "unit")["sub"] == "u");
        rejected([&] { signer.verify(token, "other"); });
        rejected([&] { signer.verify(signer.token({{"aud", "unit"}, {"exp", 1}}), "unit"); });
        rejected([&] { signer.verify(token + "00", "unit"); });
        auto normal = parse_json(R"({"a":[1,2,3],"b":true})");
        select_json_backend("fallback");
        check(parse_json(R"({"a":[1,2,3],"b":true})") == normal);
        check(json_backend() == "fallback");
        std::cout << "PASS " << checks << " checks\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
