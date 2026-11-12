#include "control/service.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <utility>

namespace control {
namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
namespace {
tcp::endpoint endpoint(const std::string &value, bool allow_loopback) {
    auto colon = value.rfind(':');
    require(colon != std::string::npos, "invalid", "Invalid endpoint");
    auto host = value.substr(0, colon);
    if (host.starts_with('[') && host.ends_with(']'))
        host = host.substr(1, host.size() - 2);
    beast::error_code error;
    auto address = net::ip::make_address(host, error);
    require(!error, "invalid", "First protocol requires numeric IP endpoints");
    auto port = std::stoul(value.substr(colon + 1));
    require(port > 0 && port <= 65535, "invalid", "Invalid port");
    bool blocked = address.is_loopback() || address.is_unspecified() || address.is_multicast();
    if (address.is_v4()) {
        auto v = address.to_v4().to_uint();
        blocked = blocked || (v >> 24) == 10 || (v >> 20) == 0xac1 || (v >> 16) == 0xc0a8 ||
                  (v >> 16) == 0xa9fe || (v >> 22) == 0x191 || (v >> 24) == 0 || (v >> 24) >= 224;
    } else {
        auto b = address.to_v6().to_bytes();
        blocked = blocked || address.to_v6().is_link_local() || address.to_v6().is_v4_mapped() ||
                  (b[0] & 0xfe) == 0xfc;
    }
    require(!blocked || (allow_loopback && address.is_loopback()), "forbidden",
            "Non-public probe endpoint rejected", 403);
    return {address, static_cast<unsigned short>(port)};
}
} // namespace
bool probe_node(const std::string &game, const std::string &proof, const std::string &key,
                bool allow_loopback) {
    auto game_address = endpoint(game, allow_loopback), proof_address = endpoint(proof, allow_loopback);
    require(game_address.address() == proof_address.address(), "invalid", "Proof and game IP must match");
    net::io_context io;
    ssl::context tls(ssl::context::tls_client);
    // Trust comes from the signed fresh nonce under the enrolled key, never this certificate.
    tls.set_verify_mode(ssl::verify_none);
    beast::ssl_stream<beast::tcp_stream> stream(io, tls);
    tcp::socket game_socket(io);
    net::steady_timer timer(io, std::chrono::seconds(3));
    auto nonce = random_id();
    bool complete = false, verified = false;
    http::request<http::string_body> request(http::verb::post, "/.well-known/buggcraft-node-proof", 11);
    request.set(http::field::host, proof);
    request.set(http::field::content_type, "application/json");
    request.body() = Json({{"nonce", nonce}, {"endpoint", game}}).dump();
    request.prepare_payload();
    beast::flat_buffer buffer;
    http::response_parser<http::string_body> response;
    response.body_limit(4096);
    auto finish = [&] {
        complete = true;
        timer.cancel();
        beast::error_code ignored;
        game_socket.close(ignored);
        beast::get_lowest_layer(stream).socket().close(ignored);
    };
    timer.async_wait([&](beast::error_code error) {
        if (!error && !complete)
            finish();
    });
    game_socket.async_connect(game_address, [&](beast::error_code error) {
        if (error || complete) {
            finish();
            return;
        }
        beast::get_lowest_layer(stream).async_connect(proof_address, [&](beast::error_code e) {
            if (e || complete) {
                finish();
                return;
            }
            stream.async_handshake(ssl::stream_base::client, [&](beast::error_code e2) {
                if (e2 || complete) {
                    finish();
                    return;
                }
                http::async_write(stream, request, [&](beast::error_code e3, std::size_t) {
                    if (e3 || complete) {
                        finish();
                        return;
                    }
                    http::async_read(stream, buffer, response, [&](beast::error_code e4, std::size_t) {
                        if (!e4 && !complete && response.get().result() == http::status::ok) {
                            try {
                                auto payload = parse_json(response.get().body());
                                auto message = "buggcraft-node-proof-v1\n" + nonce + "\n" + game;
                                verified = verify_ed25519(key, message, text(payload, "signature", 128));
                            } catch (...) {
                            }
                        }
                        finish();
                    });
                });
            });
        });
    });
    io.run();
    return verified;
}
} // namespace control
