#include "control/server.hpp"
#include "control/service.hpp"
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <chrono>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <utility>

namespace control {
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = net::ip::tcp;
using Stream = beast::ssl_stream<beast::tcp_stream>;
using Response = http::response<http::string_body>;
using Request = http::request<http::string_body>;
using Clock = std::chrono::steady_clock;
namespace {
std::string bearer_token(const Request &request) {
    auto value = request[http::field::authorization];
    constexpr std::string_view prefix = "Bearer ";
    if (std::string_view(value.data(), value.size()).substr(0, prefix.size()) != prefix)
        return {};
    return std::string(value.substr(prefix.size()));
}
Reply public_error(const Error &e) {
    return {e.status, {{"error", {{"code", e.code}, {"message", e.what()}}}}};
}
std::string client_peer(const Request &request, const std::string &transport_peer, const Config &config) {
    beast::error_code error;
    auto peer = net::ip::make_address(transport_peer, error);
    if (error || !config.browser || !config.browser->trust_loopback_proxy || !peer.is_loopback())
        return transport_peer;
    const auto header = request["X-Real-IP"];
    if (header.empty() || header.size() > 45)
        return transport_peer;
    auto forwarded = net::ip::make_address(std::string(header), error);
    return error ? transport_peer : forwarded.to_string();
}
struct State {
    Config config;
    Service service;
    std::unique_ptr<net::thread_pool> workers;
    std::string conninfo;
    std::atomic_uint jobs{0}, connections{0};
    std::atomic_bool stopping{false};
    std::mutex rate_mutex;
    std::map<std::string, std::pair<std::int64_t, unsigned>> public_rates;
    explicit State(const Config &c)
        : config(c), service(c), workers(std::make_unique<net::thread_pool>(c.workers)),
          conninfo(read_secret(c.database_file, 16384)) {}
    bool allow_peer(const std::string &peer) {
        auto now =
            std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count() / 60;
        std::lock_guard lock(rate_mutex);
        for (auto it = public_rates.begin(); it != public_rates.end();) {
            if (it->second.first != now)
                it = public_rates.erase(it);
            else
                ++it;
        }
        if (!public_rates.contains(peer) && public_rates.size() >= 4096)
            return false;
        auto &bucket = public_rates[peer];
        if (bucket.first != now)
            bucket = {now, 0};
        return ++bucket.second <= 3000;
    }
    static std::unique_ptr<Database> &worker_database() {
        thread_local std::unique_ptr<Database> database;
        return database;
    }
    template <class Result, class Work, class Failure>
    void submit(net::any_io_executor executor, Work work, std::function<void(Result)> done, Failure failure) {
        if (stopping) {
            done(failure(Error(503, "stopping", "Service stopping")));
            return;
        }
        if (jobs.fetch_add(1) >= config.queue_limit) {
            --jobs;
            done(failure(Error(503, "busy", "Request queue full; retry with backoff")));
            return;
        }
        net::post(*workers,
                  [this, executor, work = std::move(work), done = std::move(done), failure]() mutable {
                      struct Job {
                          std::atomic_uint &counter;
                          ~Job() {
                              --counter;
                          }
                      } job{jobs};
                      if (stopping)
                          return;
                      auto &database = worker_database();
                      Result reply;
                      try {
                          if (!database)
                              database = std::make_unique<Database>(conninfo);
                          reply = work(*database);
                      } catch (const Error &e) {
                          if (e.code == "storage_unavailable")
                              database.reset();
                          reply = failure(e);
                      } catch (...) {
                          reply = failure(Error(500, "internal", "Internal error"));
                      }
                      net::post(executor, [done = std::move(done), reply = std::move(reply)]() mutable {
                          done(std::move(reply));
                      });
                  });
    }
    void execute_browser(net::any_io_executor executor, BrowserRequest request,
                         std::function<void(BrowserReply)> done) {
        submit<BrowserReply>(
            executor,
            [this, request = std::move(request)](Database &db) { return service.browser(db, request); },
            std::move(done),
            [](const Error &e) {
                return BrowserReply(
                    e.status,
                    Json({{"error", e.status >= 500 ? "服务暂不可用，请稍后重试。" : e.what()}}).dump());
            });
    }
    void execute(net::any_io_executor executor, std::string path, std::string token, std::string input,
                 std::function<void(Reply)> done) {
        submit<Reply>(
            executor,
            [this, path = std::move(path), token = std::move(token), input = std::move(input)](Database &db) {
                return service.dispatch(db, path, token, parse_json(input.empty() ? "{}" : input));
            },
            std::move(done), public_error);
    }
    void maintenance() {
        if (stopping)
            return;
        if (jobs.fetch_add(1) >= config.queue_limit) {
            --jobs;
            return;
        }
        net::post(*workers, [this] {
            try {
                Database db(conninfo);
                service.maintain(db);
            } catch (...) {
                std::cerr << "maintenance: deferred\n";
            }
            --jobs;
        });
    }
};
struct ConnectionLease {
    State &state;
    explicit ConnectionLease(State &s) : state(s) {}
    ~ConnectionLease() {
        --state.connections;
    }
};
class WebSocket : public std::enable_shared_from_this<WebSocket> {
    websocket::stream<Stream> stream_;
    beast::flat_buffer buffer_;
    State &state_;
    std::shared_ptr<ConnectionLease> lease_;
    std::string token_, peer_;
    std::deque<std::string> output_;
    net::steady_timer poll_;
    std::int64_t cursor_ = 0;
    bool subscribed_ = false;

  public:
    WebSocket(Stream stream, State &state, std::shared_ptr<ConnectionLease> lease, std::string token,
              std::string peer)
        : stream_(std::move(stream)), state_(state), lease_(std::move(lease)), token_(std::move(token)),
          peer_(std::move(peer)), poll_(stream_.get_executor()) {}
    void start(Request request) {
        beast::get_lowest_layer(stream_).expires_never();
        stream_.set_option(
            websocket::stream_base::timeout{std::chrono::seconds(5), std::chrono::seconds(45), true});
        stream_.read_message_max(65536);
        stream_.async_accept(request, [self = shared_from_this()](beast::error_code error) {
            if (!error)
                self->read();
        });
    }
    void read() {
        stream_.async_read(buffer_, [self = shared_from_this()](beast::error_code error, std::size_t) {
            if (error) {
                self->close_socket();
                return;
            }
            if (!self->stream_.got_text() || !self->state_.allow_peer(self->peer_)) {
                self->close_socket();
                return;
            }
            auto raw = beast::buffers_to_string(self->buffer_.data());
            self->buffer_.consume(self->buffer_.size());
            try {
                auto envelope = parse_json(raw);
                auto path = text(envelope, "path", 128);
                require(path.starts_with("/v1/") && !path.starts_with("/v1/admin/") &&
                            path != "/v1/identity/challenge" && path != "/v1/identity/prove" &&
                            !path.starts_with("/v1/enrollment/"),
                        "forbidden", "Invalid channel operation", 403);
                auto id = text(envelope, "request_id", 64);
                require(envelope.contains("body") && envelope["body"].is_object(), "invalid",
                        "Missing channel body");
                bool subscribe = path == "/v1/social/subscribe";
                if (subscribe) {
                    self->cursor_ = integer(envelope["body"], "after", 0, INT64_MAX);
                    path = "/v1/social/inbox";
                }
                self->state_.execute(
                    self->stream_.get_executor(), path, self->token_, envelope["body"].dump(),
                    [self, id, subscribe](Reply reply) {
                        if (subscribe && reply.status == 200) {
                            self->subscribed_ = true;
                            self->cursor_ = reply.body.value("cursor", self->cursor_);
                            self->poll_events();
                        }
                        self->write({{"request_id", id}, {"status", reply.status}, {"body", reply.body}});
                        self->read();
                    });
            } catch (const Error &e) {
                auto reply = public_error(e);
                self->write({{"status", reply.status}, {"body", reply.body}});
                self->read();
            }
        });
    }
    void write(const Json &value) {
        if (output_.size() >= 8) {
            close_socket();
            return;
        }
        output_.push_back(value.dump());
        if (output_.size() == 1)
            flush();
    }
    void flush() {
        stream_.text(true);
        stream_.async_write(net::buffer(output_.front()),
                            [self = shared_from_this()](beast::error_code error, std::size_t) {
                                if (error) {
                                    self->close_socket();
                                    return;
                                }
                                self->output_.pop_front();
                                if (!self->output_.empty())
                                    self->flush();
                            });
    }
    void close_socket() {
        subscribed_ = false;
        poll_.cancel();
        beast::error_code ignored;
        beast::get_lowest_layer(stream_).socket().close(ignored);
    }
    void poll_events() {
        poll_.expires_after(std::chrono::seconds(1));
        poll_.async_wait([weak = weak_from_this()](beast::error_code error) {
            auto self = weak.lock();
            if (!self || error || !self->subscribed_)
                return;
            self->state_.execute(self->stream_.get_executor(), "/v1/social/inbox", self->token_,
                                 Json({{"after", self->cursor_}}).dump(), [self](Reply reply) {
                                     if (reply.status == 401 || reply.status == 403) {
                                         self->close_socket();
                                         return;
                                     }
                                     if (reply.status == 200 && !reply.body["events"].empty()) {
                                         self->cursor_ = reply.body.value("cursor", self->cursor_);
                                         self->write({{"event", "social"}, {"body", reply.body}});
                                     }
                                     if (self->subscribed_)
                                         self->poll_events();
                                 });
        });
    }
};
class HttpSession : public std::enable_shared_from_this<HttpSession> {
    Stream stream_;
    beast::flat_buffer buffer_;
    std::unique_ptr<http::request_parser<http::string_body>> parser_;
    std::shared_ptr<Response> response_;
    State &state_;
    std::shared_ptr<ConnectionLease> lease_;
    std::string peer_;
    unsigned requests_ = 0;

  public:
    HttpSession(tcp::socket socket, ssl::context &tls, State &state)
        : stream_(std::move(socket), tls), state_(state), lease_(std::make_shared<ConnectionLease>(state)) {
        beast::error_code error;
        auto endpoint = beast::get_lowest_layer(stream_).socket().remote_endpoint(error);
        peer_ = error ? "unknown" : endpoint.address().to_string();
        beast::get_lowest_layer(stream_).socket().set_option(tcp::no_delay(true), error);
    }
    void start() {
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(5));
        stream_.async_handshake(ssl::stream_base::server,
                                [self = shared_from_this()](beast::error_code error) {
                                    if (!error)
                                        self->read();
                                });
    }
    void read() {
        parser_ = std::make_unique<http::request_parser<http::string_body>>();
        parser_->body_limit(65536);
        parser_->header_limit(16384);
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(15));
        http::async_read(
            stream_, buffer_, *parser_, [self = shared_from_this()](beast::error_code error, std::size_t) {
                if (error)
                    return;
                auto request = std::make_shared<Request>(self->parser_->release());
                bool channel = websocket::is_upgrade(*request) && request->target() == "/v1/channel";
                const auto request_peer = client_peer(*request, self->peer_, self->state_.config);
                if (!self->state_.allow_peer(request_peer)) {
                    self->respond({429, {{"error", {{"code", "rate_limited"}}}}}, false);
                    return;
                }
                if (self->state_.config.browser &&
                    !std::string_view(request->target().data(), request->target().size())
                         .starts_with("/v1/")) {
                    BrowserRequest browser;
                    browser.user_agent = std::string((*request)[http::field::user_agent]).substr(0, 512);
                    browser.method = std::string(request->method_string());
                    browser.target = std::string(request->target());
                    browser.origin = std::string((*request)[http::field::origin]);
                    browser.cookie = std::string((*request)[http::field::cookie]);
                    browser.csrf = std::string((*request)["X-Account-CSRF"]);
                    browser.content_type = std::string((*request)[http::field::content_type]);
                    browser.peer = request_peer;
                    try {
                        if (!request->body().empty())
                            browser.body = parse_json(request->body());
                    } catch (...) {
                        self->respond_browser({400, R"({"error":"输入无效，请检查后重试。"})"}, false);
                        return;
                    }
                    self->state_.execute_browser(self->stream_.get_executor(), std::move(browser),
                                                 [self, request](BrowserReply reply) {
                                                     self->respond_browser(std::move(reply),
                                                                           request->keep_alive() &&
                                                                               ++self->requests_ < 100);
                                                 });
                    return;
                }
                if (!channel && request->method() != http::verb::post) {
                    self->respond({405, {{"error", {{"code", "method_not_allowed"}}}}}, false);
                    return;
                }
                if (!channel && request->target() != "/v1/health" &&
                    request->find(http::field::content_type) == request->end()) {
                    self->respond({415, {{"error", {{"code", "json_required"}}}}}, false);
                    return;
                }
                auto token = bearer_token(*request);
                auto path = channel ? "/v1/channel/open" : std::string(request->target());
                self->state_.execute(
                    self->stream_.get_executor(), path, token, request->body(),
                    [self, request, token, channel](Reply reply) {
                        if (channel && reply.status == 200) {
                            std::make_shared<WebSocket>(std::move(self->stream_), self->state_, self->lease_,
                                                        token, self->peer_)
                                ->start(std::move(*request));
                        } else
                            self->respond(std::move(reply), request->keep_alive() && ++self->requests_ < 100);
                    });
            });
    }
    void respond(Reply reply, bool keep_alive) {
        respond_browser(BrowserReply(reply.status, reply.body.dump()), keep_alive);
    }
    void respond_browser(BrowserReply reply, bool keep_alive) {
        response_ = std::make_shared<Response>(http::status(reply.status), 11);
        response_->set(http::field::content_type, reply.content_type);
        response_->set(http::field::cache_control, reply.content_type.starts_with("text/css") ||
                                                           reply.content_type.starts_with("text/javascript")
                                                       ? "public, max-age=31536000, immutable"
                                                       : "no-store");
        response_->set(http::field::server, "buggcraft-control");
        if (reply.status == 429 || reply.status == 503)
            response_->set(http::field::retry_after, "2");
        response_->set("X-Content-Type-Options", "nosniff");
        response_->set("X-Robots-Tag", "noindex, nofollow");
        response_->set("Referrer-Policy", "no-referrer");
        response_->set("Strict-Transport-Security", "max-age=86400");
        response_->set("Content-Security-Policy",
                       "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        if (!reply.cookie.empty())
            response_->set(http::field::set_cookie, reply.cookie);
        if (!reply.location.empty())
            response_->set(http::field::location, reply.location);
        response_->keep_alive(keep_alive);
        response_->body() = std::move(reply.body);
        response_->prepare_payload();
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(5));
        http::async_write(stream_, *response_,
                          [self = shared_from_this(), keep_alive](beast::error_code error, std::size_t) {
                              if (!error && keep_alive)
                                  self->read();
                              else if (!error)
                                  self->stream_.async_shutdown([self](beast::error_code) {});
                          });
    }
};
class Listener : public std::enable_shared_from_this<Listener> {
    net::io_context &io_;
    tcp::acceptor acceptor_;
    ssl::context &tls_;
    State &state_;

  public:
    Listener(net::io_context &io, ssl::context &tls, State &state)
        : io_(io), acceptor_(io, {net::ip::make_address(state.config.listen), state.config.port}), tls_(tls),
          state_(state) {}
    void accept() {
        acceptor_.async_accept(
            net::make_strand(io_), [self = shared_from_this()](beast::error_code error, tcp::socket socket) {
                if (!error) {
                    if (self->state_.connections.fetch_add(1) < self->state_.config.max_connections)
                        std::make_shared<HttpSession>(std::move(socket), self->tls_, self->state_)->start();
                    else {
                        --self->state_.connections;
                        beast::error_code ignored;
                        socket.close(ignored);
                    }
                }
                if (!self->state_.stopping)
                    self->accept();
            });
    }
};
} // namespace
int run_server(const Config &config) {
    select_json_backend(config.json_implementation);
    State state(config);
    Database migration(state.conninfo);
    migration.migrate(read_file(config.schema_file));
    net::io_context io(int(config.io_threads));
    ssl::context tls(ssl::context::tls_server);
    SSL_CTX_set_min_proto_version(tls.native_handle(), TLS1_2_VERSION);
    tls.set_options(ssl::context::no_sslv2 | ssl::context::no_sslv3 | ssl::context::no_compression);
    (void)read_secret(config.tls_key);
    tls.use_certificate_chain_file(config.tls_certificate);
    tls.use_private_key_file(config.tls_key, ssl::context::pem);
    std::make_shared<Listener>(io, tls, state)->accept();
    net::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](beast::error_code, int) {
        state.stopping = true;
        io.stop();
    });
    net::steady_timer maintenance(io);
    std::function<void()> schedule;
    schedule = [&] {
        maintenance.expires_after(std::chrono::seconds(60));
        maintenance.async_wait([&](beast::error_code error) {
            if (!error && !state.stopping) {
                state.maintenance();
                schedule();
            }
        });
    };
    schedule();
    std::cout << Json({{"status", "listening"},
                       {"address", config.listen},
                       {"port", config.port},
                       {"version", CONTROL_VERSION},
                       {"json_backend", json_backend()}})
                     .dump()
              << std::endl;
    std::vector<std::thread> threads;
    for (unsigned i = 1; i < config.io_threads; ++i)
        threads.emplace_back([&] { io.run(); });
    io.run();
    for (auto &thread : threads)
        thread.join();
    state.stopping = true;
    state.workers->stop();
    state.workers->join();
    // Release queued session references before io_context and State are destroyed.
    state.workers.reset();
    return 0;
}
} // namespace control
