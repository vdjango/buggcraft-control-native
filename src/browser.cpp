#include "control/service.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <regex>
#include <set>

namespace control {
namespace {
std::string canonical(const Json &value) {
    return value.dump(-1, ' ', true);
}
std::string lower(std::string value) {
    for (auto &c : value)
        c = char(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
const Json &account_policy() {
    static const Json policy = {
        {"minimum_length", 6},
        {"maximum_length", 256},
        {"blocked_passwords",
         {"123456",    "1234567",     "12345678",   "123456789", "1234567890", "654321",    "111111",
          "000000",    "666666",      "888888",     "999999",    "abcdef",     "abcdefg",   "abc123",
          "abc123456", "qwerty",      "qwertyuiop", "qwe123",    "password",   "password1", "password123",
          "admin123",  "admin123456", "letmein",    "welcome",   "iloveyou",   "minecraft", "buggcraft",
          "asdfgh",    "zxcvbn",      "a123456",    "123abc",    "112233",     "121212"}},
        {"reserved_names",
         {"admin", "administrator", "root", "official", "support", "moderator", "system", "bugg", "buggcraft",
          "staff", "security", "service", "webmaster"}}};
    return policy;
}
void validate_name(const std::string &name) {
    require(std::regex_match(name, std::regex("[A-Za-z0-9_-]{3,32}")), "invalid",
            "用户名需要 3–32 位字母、数字、下划线或短横线。");
    auto normalized = lower(name);
    for (const auto &reserved : account_policy().at("reserved_names")) {
        auto prefix = reserved.get<std::string>();
        require(normalized != prefix &&
                    !(normalized.starts_with(prefix) && normalized.size() > prefix.size() &&
                      std::string("0123456789_-").find(normalized[prefix.size()]) != std::string::npos),
                "reserved_name", "此用户名为系统或管理身份保留，请换一个名字。");
    }
}
void validate_password(const Json &body, const std::string &username) {
    (void)integer(body, "password_length", 6, 256);
    auto digest = text(body, "password_digest", 64);
    require(digest.size() == 64 && unhex(digest).size() == 32, "invalid", "密码检查数据无效。");
    for (const auto &password : account_policy().at("blocked_passwords"))
        require(!secure_equal(digest, sha256(password.get<std::string>())), "weak_password",
                "这个密码太常见，请换一个至少 6 位的密码。");
    require(!secure_equal(digest, sha256(lower(username))), "weak_password", "密码不能与用户名相同。");
}
Json client_description(std::string agent) {
    auto contains = [&](const char *s) { return agent.find(s) != std::string::npos; };
    std::string system = contains("Android")                           ? "Android"
                         : contains("iPhone") || contains("iPad")      ? "iOS / iPadOS"
                         : contains("Windows")                         ? "Windows"
                         : contains("Macintosh") || contains("Mac OS") ? "macOS"
                         : contains("Linux")                           ? "Linux"
                                                                       : "未知系统";
    std::string browser = contains("Edg/") || contains("EdgA/") || contains("EdgiOS/") ? "Microsoft Edge"
                          : contains("Firefox/") || contains("FxiOS/")                 ? "Firefox"
                          : contains("Chrome/") || contains("CriOS/")                  ? "Chrome"
                          : contains("Safari/")                                        ? "Safari"
                                                                                       : "未知浏览器";
    return {{"system", system}, {"browser", browser}};
}
Json value(Database &db, const std::string &kind, const std::string &id, bool consume = false,
           bool lock = false) {
    auto rows = db.query(
        consume
            ? "DELETE FROM browser_values WHERE kind=$1 AND id=$2 AND expires_at>clock_timestamp() "
              "RETURNING body"
            : ("SELECT body FROM browser_values WHERE kind=$1 AND id=$2 AND expires_at>clock_timestamp()" +
               std::string(lock ? " FOR UPDATE" : "")),
        {kind, sha256(id)});
    require(rows.size() == 1, "expired", "请求已过期，请重新开始。", 410);
    return rows.json(0);
}
void put(Database &db, const std::string &kind, const std::string &id, const Json &body, int lifetime,
         int limit = 512) {
    db.lock("browser-values:" + kind);
    auto count = db.query(
        "SELECT count(*) FROM browser_values WHERE kind=$1 AND id<>$2 AND expires_at>clock_timestamp()",
        {kind, sha256(id)});
    require(count.number(0) < limit, "capacity", "请求过多，请稍后重试。", 429);
    db.query("INSERT INTO browser_values(kind,id,body,expires_at) "
             "VALUES($1,$2,$3::jsonb,clock_timestamp()+$4::integer*interval '1 second') "
             "ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body,expires_at=excluded.expires_at",
             {kind, sha256(id), body.dump(), std::to_string(lifetime)});
}
Json account(Database &db, const std::string &identifier, bool resolve = false) {
    auto rows =
        db.query(resolve ? "SELECT record FROM browser_accounts WHERE (id=$1 OR "
                           "lower(username)=lower($1)) AND NOT blocked LIMIT 2 FOR SHARE"
                         : "SELECT record FROM browser_accounts WHERE id=$1 AND NOT blocked FOR SHARE",
                 {identifier});
    require(rows.size() == 1, "unknown_account", "账号不存在或用户名不唯一，请使用完整账号 ID。", 400);
    return rows.json(0);
}
bool active(const Json &device) {
    auto now = unix_seconds();
    const auto &grant = device.at("grant");
    return !device.value("revoked", true) && grant.at("e").get<int64_t>() > now &&
           device.at("last_used").get<double>() + 30 * 86400 > double(now);
}
int64_t device_expiry(const Json &device) {
    return std::min(device.at("grant").at("e").get<int64_t>(),
                    int64_t(device.at("last_used").get<double>() + 30 * 86400));
}
void check_key(const Json &key) {
    (void)verify_account_proof(key.dump(), "key-validation", "AA");
}
void check_signature(const Json &key, const std::string &message, const std::string &signature) {
    require(verify_account_proof(key.dump(), message, signature), "unauthorized",
            "签名验证失败，请重新登录。", 401);
}
void check_state(const Json &state, const std::string &id, bool initial = true) {
    require(state.is_object() && state.size() == 3 && state.value("account", "") == id &&
                state.at("revision").is_number_integer() && state.at("revision").get<int64_t>() >= 1 &&
                state.at("revision").get<int64_t>() <= (initial ? 1 : INT32_MAX),
            "invalid", "账号状态无效。");
    const auto &box = state.at("box");
    require(box.is_object() && box.size() == 4 && box.value("iterations", 0) == 600000 &&
                decode_base64(text(box, "salt", 32)).size() == 16 &&
                decode_base64(text(box, "iv", 24)).size() == 12,
            "invalid", "账号加密数据无效。");
    auto size = decode_base64(text(box, "ciphertext", 6000)).size();
    require(size >= 32 && size <= 4096, "invalid", "账号加密数据无效。");
}
std::string cookie_value(const std::string &header) {
    std::size_t begin = 0;
    while (begin < header.size()) {
        auto end = header.find(';', begin);
        auto item = header.substr(begin, end == std::string::npos ? end : end - begin);
        while (!item.empty() && item.front() == ' ')
            item.erase(item.begin());
        if (item.starts_with("account_session="))
            return item.substr(16);
        if (end == std::string::npos)
            break;
        begin = end + 1;
    }
    return {};
}
Json session(Database &db, const BrowserRequest &request, bool write) {
    Json result;
    try {
        result = value(db, "session", cookie_value(request.cookie));
        (void)account(db, text(result, "account", 80));
    } catch (const Error &) {
        throw Error(401, "unauthorized", "请先登录联机账号。");
    }
    if (write)
        require(secure_equal(request.csrf, text(result, "csrf", 96)), "csrf", "请刷新页面后重试。", 403);
    return result;
}
bool smtp_enabled(const Json &settings) {
    return !settings.value("username", "").empty() && !settings.value("password", "").empty();
}
std::string verify_mail(const Json &proof, const Json &body, const std::string &purpose,
                        const std::string &nonce, const std::string &username = "") {
    require(proof.value("purpose", "") == purpose && proof.value("nonce", "") == nonce &&
                proof.value("username", "") == lower(username) &&
                secure_equal(text(proof, "code", 64), sha256(text(body, "code", 6))),
            "invalid", "邮箱验证码无效或已过期，请重新发送。");
    return text(proof, "mailbox", 64);
}
Json mail_candidates(Database &db, const std::string &mailbox) {
    auto rows = db.query("SELECT a.id,a.username,m.preferred,(a.record->'state'->>'revision')::bigint FROM "
                         "browser_mailboxes m JOIN browser_accounts "
                         "a ON a.id=m.account_id "
                         "WHERE mailbox=$1 AND NOT a.blocked ORDER BY m.preferred DESC,a.id LIMIT 64",
                         {mailbox});
    Json result = Json::array();
    for (int i = 0; i < rows.size(); ++i) {
        auto id = rows.at(i, 0);
        result.push_back({{"account", id},
                          {"username", rows.at(i, 1)},
                          {"home", id.substr(id.find('.') + 1)},
                          {"revision", rows.number(i, 3)},
                          {"preferred", rows.at(i, 2) == "t"}});
    }
    return result;
}
void choose_mail(Database &db, const std::string &mailbox, const std::string &id) {
    auto count =
        db.query("SELECT 1 FROM browser_mailboxes WHERE mailbox=$1 AND account_id=$2", {mailbox, id});
    require(count.size() == 1, "invalid", "请选择已验证邮箱所属的账号。");
    db.query("UPDATE browser_mailboxes SET preferred=(account_id=$2) WHERE mailbox=$1", {mailbox, id});
}
void rate(Database &db, const std::string &key, int limit, int seconds = 60) {
    auto rows =
        db.query("INSERT INTO rate_buckets(key,window_id,count) VALUES($1,$2::bigint,1) ON CONFLICT(key) "
                 "DO UPDATE SET count=CASE WHEN rate_buckets.window_id=excluded.window_id THEN "
                 "rate_buckets.count+1 ELSE 1 END,window_id=excluded.window_id RETURNING count",
                 {"browser:" + key, std::to_string(unix_seconds() / seconds)});
    require(rows.number(0) <= limit, "rate_limited", "请求过多，请稍后重试。", 429);
}
std::string query_decode(std::string_view value) {
    std::string output;
    for (std::size_t i = 0; i < value.size(); ++i) {
        char c = value[i];
        if (c == '+')
            c = ' ';
        else if (c == '%') {
            require(i + 2 < value.size(), "invalid", "Invalid query encoding");
            auto pair = std::string(value.substr(i + 1, 2));
            for (auto &p : pair)
                p = char(std::tolower(static_cast<unsigned char>(p)));
            c = unhex(pair)[0];
            i += 2;
        }
        output.push_back(c);
    }
    return output;
}
} // namespace

BrowserReply Service::browser(Database &db, const BrowserRequest &request) {
    require(config_.browser.has_value(), "not_found", "Not found", 404);
    const auto &config = *config_.browser;
    BrowserReply reply;
    auto split = request.target.find('?');
    auto path = request.target.substr(0, split);
    require(request.target.size() <= 2048, "invalid", "Request target exceeds limit");
    if (request.method == "GET" && !path.starts_with("/api/")) {
        static const std::set<std::string> pages = {"/login",          "/register",        "/account",
                                                    "/account/access", "/account/devices", "/account/email",
                                                    "/launcher-login", "/forgot-password"};
        if (path == "/") {
            reply.status = 302;
            reply.location = "/account";
            return reply;
        }
        std::string name;
        if (pages.contains(path))
            name = "account.html";
        else if (std::regex_match(
                     path,
                     std::regex(
                         R"(/vue-(?:page-account|runtime)-[A-Za-z0-9_-]+\.js|/vue-[A-Za-z0-9_-]+\.css|/vue-bugg-landscape-[A-Za-z0-9_-]+\.webp)")))
            name = path.substr(1);
        else
            throw Error(404, "not_found", "Not found");
        auto file = std::filesystem::path(config.assets) / name;
        require(std::filesystem::is_regular_file(file), "not_found", "Not found", 404);
        reply.body = read_file(file.string(), 262144);
        reply.content_type = name.ends_with(".css")   ? "text/css; charset=utf-8"
                             : name.ends_with(".js")  ? "text/javascript; charset=utf-8"
                             : name.ends_with(".webp") ? "image/webp"
                                                       : "text/html; charset=utf-8";
        return reply;
    }
    require(request.method == "POST" || request.method == "GET", "method_not_allowed", "Method not allowed",
            405);
    if (request.method == "POST") {
        require(request.content_type.starts_with("application/json"), "json_required", "JSON required", 415);
        require(request.origin.empty() || request.origin == config.origin, "origin", "请求来源无效。", 403);
    }
    require(request.body.is_object(), "invalid", "Invalid request");
    std::map<std::string, std::string> query;
    if (split != std::string::npos) {
        std::string rest = request.target.substr(split + 1);
        while (!rest.empty()) {
            auto next = rest.find('&');
            auto pair = rest.substr(0, next);
            auto equal = pair.find('=');
            require(equal != std::string::npos && query.size() < 8, "invalid", "Invalid query");
            query[query_decode(pair.substr(0, equal))] = query_decode(pair.substr(equal + 1));
            if (next == std::string::npos)
                break;
            rest.erase(0, next + 1);
        }
    }
    {
        Transaction limiting(db);
        rate(db, sha256(request.peer + ":" + path), path == "/api/account/email-code" ? 10 : 120);
        limiting.commit();
    }
    // Burn proofs before business validation. A rejected signature or code cannot
    // restore a nonce by rolling back the account/device transaction.
    Json proofs = Json::object();
    {
        Transaction consumption(db);
        auto take = [&](const char *kind, const char *field) {
            proofs[kind] = value(db, kind, text(request.body, field, 96), true);
        };
        if (path == "/api/account/register")
            take("enroll", "nonce");
        if (path == "/api/account/login")
            take("login", "nonce");
        if (path == "/api/launcher/refresh")
            take("device-challenge", "nonce");
        if (path == "/api/account/email-challenge" || path == "/api/account/email-accounts" ||
            path == "/api/account/recovery-verify")
            take("mail-ticket", "ticket");
        if (path == "/api/account/recovery-reset")
            take("recovery-grant", "grant");
        if (path == "/api/account/register" && !request.body.value("email_ticket", "").empty())
            take("mail-ticket", "email_ticket");
        if (path == "/api/account/login" && !request.body.value("email_grant", "").empty())
            take("email-grant", "email_grant");
        consumption.commit();
    }
    Transaction transaction(db);
    reply.body = browser_api(db, request, path, query, proofs, reply).dump();
    require(reply.body.size() <= 262144, "too_large", "Response exceeds limit", 413);
    transaction.commit();
    return reply;
}

Json Service::browser_api(Database &db, const BrowserRequest &request, const std::string &path,
                          const std::map<std::string, std::string> &query, const Json &proofs,
                          BrowserReply &reply) {
    const auto &config = *config_.browser;
    const auto &body = request.body;
    auto issuer = sha256(config.issuer_public).substr(0, 32);
    const auto &audience_key = browser_audience_;
    auto proof = [&](const std::string &id) { return hmac_sha256(audience_key, id); };
    auto signature = [&](const Json &message) {
        return ssh_signature(browser_signer_->sign(canonical(message)));
    };
    auto load_device = [&](const std::string &id) {
        auto rows = db.query("SELECT body FROM browser_devices WHERE id=$1 FOR UPDATE", {id});
        require(rows.size() == 1, "unauthorized", "设备授权已失效，请重新登录。", 401);
        auto device = rows.json(0);
        require(active(device), "unauthorized", "设备授权已失效，请重新登录。", 401);
        (void)account(db, text(device.at("grant"), "a", 80));
        return device;
    };
    auto authorize_device = [&](const std::string &id, const Json &device) {
        const auto &grant = device.at("grant");
        auto record = account(db, text(grant, "a", 80));
        return admin(db, "/v1/admin/device/authorize",
                     {{"certificate", record.at("certificate")},
                      {"issuer_signature", record.at("issuer_signature")},
                      {"device_id", id},
                      {"device_grant", grant},
                      {"delegation_signature", device.at("signature")},
                      {"expires_at", device_expiry(device)}});
    };
    auto profile = [&](const std::string &id, const Json &device) {
        const auto &grant = device.at("grant");
        auto account_id = text(grant, "a", 80);
        auto record = account(db, account_id);
        Json claims = {{"a", account_id},
                       {"i", issuer},
                       {"e", std::min(grant.at("e").get<int64_t>(), unix_seconds() + 7 * 86400)},
                       {"n", grant.at("n")},
                       {"g", grant},
                       {"s", device.at("signature")}};
        auto token = "acct1." + base64url(canonical(claims)) + "." + signature(claims);
        Json control = {{"origin", config.origin},
                        {"signing_public_key", signer_.public_key()},
                        {"ca_pem", config.client_ca},
                        {"protocol", 1},
                        {"region", config.region},
                        {"operator", config.operator_name},
                        {"certificate", record.at("certificate")},
                        {"issuer_signature", record.at("issuer_signature")}};
        return Json{{"profile",
                     {{"server_host", "127.0.0.1"},
                      {"server_port", 1},
                      {"server_public_key", config.issuer_public},
                      {"token", token},
                      {"control", control}}},
                    {"id", id},
                    {"name", config.name},
                    {"region", config.region},
                    {"expires_at", device_expiry(device)}};
    };
    if (path == "/api/account/policy" && request.method == "GET")
        return account_policy();
    if (path == "/api/status" && request.method == "GET")
        return {{"role", "control"},
                {"launcher_login", 1},
                {"registration_open", config.registration_open},
                {"email_verification", browser_smtp_.value("required", true)}};
    if (path == "/api/account/enroll" && request.method == "POST") {
        require(config.registration_open, "forbidden", "此服务暂未开放注册。", 403);
        auto id = random_id().substr(0, 32) + "." + issuer, nonce = random_id();
        auto message =
            "buggcraft-account-v1\nenroll\n" + issuer + "\n" + config.origin + "\n" + id + "\n" + nonce;
        put(db, "enroll", nonce, {{"account", id}, {"message", message}}, 600, 256);
        return {{"account", id}, {"nonce", nonce}, {"message", message}, {"iterations", 600000}};
    }
    if (path == "/api/account/register" && request.method == "POST") {
        require(config.registration_open, "forbidden", "此服务暂未开放注册。", 403);
        auto name = text(body, "username", 32);
        validate_name(name);
        validate_password(body, name);
        auto nonce = text(body, "nonce", 96);
        const auto &enrollment = proofs.at("enroll");
        auto id = text(enrollment, "account", 80);
        std::string mailbox;
        if (browser_smtp_.value("required", true) || body.contains("email_ticket")) {
            // Empty optional ticket from the no-mail browser form is not proof.
            if (browser_smtp_.value("required", true) || !body.value("email_ticket", "").empty())
                mailbox = verify_mail(proofs.value("mail-ticket", Json::object()),
                                      {{"code", body.value("email_code", "")}}, "register", nonce, name);
        }
        check_key(body.at("public_key"));
        check_state(body.at("state"), id);
        check_signature(body.at("public_key"), text(enrollment, "message", 2048), text(body, "proof", 256));
        check_signature(body.at("public_key"), canonical(body.at("state")), text(body, "signature", 256));
        idempotency_lock(db, "browser", "register");
        auto count = db.query("SELECT count(*) FROM browser_accounts");
        require(count.number(0) < 1000000, "capacity", "注册容量已满。", 503);
        Json certificate = {{"uid", id.substr(0, 32)},
                            {"home", issuer},
                            {"home_key", config.issuer_public},
                            {"username", name},
                            {"public_key", body.at("public_key")},
                            {"created", double(unix_seconds())}};
        Json record = {{"certificate", certificate},
                       {"issuer_signature", signature(certificate)},
                       {"state", body.at("state")},
                       {"signature", body.at("signature")}};
        (void)legacy_identity(certificate, text(record, "issuer_signature", 1024));
        db.query("INSERT INTO browser_accounts(id,username,record) VALUES($1,$2,$3::jsonb)",
                 {id, name, record.dump()});
        if (!mailbox.empty())
            db.query("INSERT INTO browser_mailboxes(mailbox,account_id) VALUES($1,$2)", {mailbox, id});
        reply.status = 201;
        return {{"account", id}};
    }
    if (path == "/api/account/challenge" && request.method == "POST") {
        auto record = account(db, text(body, "account", 256), true);
        auto id = text(record.at("state"), "account", 80), nonce = random_id();
        Json message = {{"a", id},
                        {"i", issuer},
                        {"e", unix_seconds() + 7 * 86400},
                        {"n", proof("account-audience").substr(0, 24)},
                        {"p", "buggcraft-account-login-v2"},
                        {"o", config.origin},
                        {"r", nonce}};
        if (body.contains("delegation")) {
            check_key(body.at("delegation"));
            message["d"] = body.at("delegation");
        }
        put(db, "login", nonce, {{"account", id}, {"message", canonical(message)}}, 60, 256);
        return {{"nonce", nonce}, {"message", canonical(message)}, {"record", record}};
    }
    if (path == "/api/account/login" && request.method == "POST") {
        const auto &login = proofs.at("login");
        auto id = text(login, "account", 80);
        auto record = account(db, id);
        check_signature(record.at("certificate").at("public_key"), text(login, "message", 4096),
                        text(body, "signature", 256));
        if (!body.value("email_grant", "").empty()) {
            const auto &grant = proofs.at("email-grant");
            choose_mail(db, text(grant, "mailbox", 64), id);
        }
        auto token = random_id(), csrf = random_id();
        put(db, "session", token,
            {{"account", id},
             {"csrf", csrf},
             {"client", client_description(request.user_agent)},
             {"created", unix_seconds()},
             {"last_used", unix_seconds()}},
            3600, 4096);
        reply.cookie =
            "account_session=" + token + "; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/";
        return {{"account", id}, {"csrf", csrf}};
    }
    if (path == "/api/account/me" && request.method == "GET") {
        auto current = session(db, request, false);
        auto record = account(db, text(current, "account", 80));
        db.query("UPDATE browser_values SET body=jsonb_set(body,'{last_used}',to_jsonb($2::bigint)) WHERE "
                 "kind='session' AND id=$1",
                 {sha256(cookie_value(request.cookie)), std::to_string(unix_seconds())});
        return {{"account", current.at("account")},
                {"username", record.at("certificate").at("username")},
                {"csrf", current.at("csrf")},
                {"revision", record.at("state").at("revision")},
                {"home", record.at("certificate").at("home")}};
    }
    if (path == "/api/account/memories" && request.method == "GET") {
        auto current = session(db, request, false);
        auto id = text(current, "account", 80);
        auto result = activity(db, id);
        result["joined_at"] = account(db, id).at("certificate").at("created");
        return result;
    }
    if (path == "/api/account/sessions" && request.method == "GET") {
        auto current = session(db, request, false);
        auto rows =
            db.query("SELECT id,body FROM browser_values WHERE kind='session' AND body->>'account'=$1 "
                     "AND expires_at>clock_timestamp() ORDER BY (body->>'created')::bigint DESC NULLS "
                     "LAST,id LIMIT 64",
                     {text(current, "account", 80)});
        Json sessions = Json::array();
        for (int i = 0; i < rows.size(); ++i) {
            auto data = rows.json(i, 1);
            sessions.push_back({{"id", rows.at(i, 0)},
                                {"current", rows.at(i, 0) == sha256(cookie_value(request.cookie))},
                                {"client", data.value("client", client_description(""))},
                                {"created", data.value("created", int64_t(0))},
                                {"last_used", data.value("last_used", int64_t(0))}});
        }
        return {{"sessions", sessions}};
    }
    if (path == "/api/account/session-revoke" && request.method == "POST") {
        auto current = session(db, request, true);
        auto removed = db.query(
            "DELETE FROM browser_values WHERE kind='session' AND id=$1 AND body->>'account'=$2 RETURNING id",
            {text(body, "id", 64), text(current, "account", 80)});
        require(removed.size() == 1, "not_found", "网页会话已退出。", 404);
        return {{"ok", true}};
    }
    if (path == "/api/account/logout" && request.method == "POST") {
        (void)session(db, request, true);
        (void)value(db, "session", cookie_value(request.cookie), true);
        reply.cookie = "account_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/";
        return {{"ok", true}};
    }
    if (path == "/api/launcher/start" && request.method == "POST") {
        check_key(body.at("key"));
        auto name = text(body, "name", 64);
        require(body.value("remember", Json(true)).is_boolean(), "invalid", "Invalid remember choice");
        auto id = random_id().substr(0, 32), nonce = random_id();
        put(db, "launcher", id,
            {{"key", body.at("key")},
             {"name", name},
             {"remember", body.value("remember", true)},
             {"nonce", nonce},
             {"client", client_description(request.user_agent)}},
            600, 256);
        return {{"id", id},
                {"nonce", nonce},
                {"expires_in", 600},
                {"interval", 3},
                {"verification_uri", config.origin + "/account/access?launcher=" + id}};
    }
    if (path == "/api/launcher/info" && request.method == "GET") {
        auto it = query.find("id");
        require(it != query.end(), "invalid", "Missing request ID");
        auto pending = value(db, "launcher", it->second);
        return {{"name", pending.at("name")},
                {"remember", pending.at("remember")},
                {"fingerprint", sha256(canonical(pending.at("key"))).substr(0, 16)}};
    }
    if (path == "/api/launcher/prepare" && request.method == "POST") {
        auto current = session(db, request, true);
        auto id = text(body, "id", 32);
        auto pending = value(db, "launcher", id, false, true);
        require(!pending.contains("device"), "conflict", "此设备已完成授权。", 409);
        auto now = unix_seconds();
        Json grant = {{"a", current.at("account")},
                      {"i", issuer},
                      {"n", proof("account-audience").substr(0, 24)},
                      {"p", "buggcraft-launcher-device-v1"},
                      {"o", config.origin},
                      {"r", id},
                      {"b", now},
                      {"e", now + (pending.at("remember").get<bool>() ? 180 * 86400 : 8 * 3600)},
                      {"d", pending.at("key")}};
        pending["grant"] = grant;
        put(db, "launcher", id, pending, 600, 256);
        return {{"grant", grant}};
    }
    if (path == "/api/launcher/approve" && request.method == "POST") {
        auto current = session(db, request, true);
        auto id = text(body, "id", 32);
        auto pending = value(db, "launcher", id, false, true);
        require(pending.contains("grant") && !pending.contains("device") &&
                    pending.at("grant").at("a") == current.at("account"),
                "conflict", "登录请求已变更，请重新确认。", 409);
        auto record = account(db, text(current, "account", 80));
        check_signature(record.at("certificate").at("public_key"), canonical(pending.at("grant")),
                        text(body, "signature", 256));
        idempotency_lock(db, text(current, "account", 80), "browser-devices");
        auto count =
            db.query("SELECT count(*) FROM browser_devices WHERE account_id=$1 AND "
                     "(body->>'revoked')::boolean=false AND (body->'grant'->>'e')::bigint>$2::bigint "
                     "AND (body->>'last_used')::double precision>$2::bigint-2592000",
                     {text(current, "account", 80), std::to_string(unix_seconds())});
        require(count.number(0) < 8, "capacity", "登录设备数量已达上限，请先撤销旧设备。", 409);
        Json device = {{"grant", pending.at("grant")},
                       {"signature", body.at("signature")},
                       {"name", pending.at("name")},
                       {"last_used", double(unix_seconds())},
                       {"revoked", false},
                       {"client", pending.value("client", client_description(""))}};
        db.query("INSERT INTO browser_devices(id,account_id,body) VALUES($1,$2,$3::jsonb)",
                 {id, text(current, "account", 80), device.dump()});
        (void)authorize_device(id, device);
        pending["device"] = id;
        put(db, "launcher", id, pending, 600, 256);
        return {{"ok", true}};
    }
    if (path == "/api/launcher/poll" && request.method == "POST") {
        auto id = text(body, "id", 32);
        auto pending = value(db, "launcher", id);
        check_signature(
            pending.at("key"),
            canonical({{"p", "buggcraft-launcher-poll-v1"}, {"id", id}, {"nonce", pending.at("nonce")}}),
            text(body, "signature", 256));
        if (!pending.contains("device"))
            return {{"status", "pending"}};
        auto device = load_device(id);
        (void)authorize_device(id, device);
        auto result = profile(id, device);
        result["status"] = "approved";
        return result;
    }
    if (path == "/api/launcher/challenge" && request.method == "POST") {
        auto id = text(body, "id", 32);
        require(std::regex_match(id, std::regex("[0-9a-f]{32}")), "invalid", "Invalid device ID");
        auto nonce = random_id();
        Json message = {{"p", "buggcraft-launcher-refresh-v1"},
                        {"id", id},
                        {"nonce", nonce},
                        {"i", issuer},
                        {"o", config.origin}};
        put(db, "device-challenge", nonce, message, 60);
        return {{"message", message}};
    }
    if (path == "/api/launcher/refresh" && request.method == "POST") {
        const auto &message = proofs.at("device-challenge");
        auto id = text(message, "id", 32);
        auto device = load_device(id);
        check_signature(device.at("grant").at("d"), canonical(message), text(body, "signature", 256));
        device["last_used"] = double(unix_seconds());
        db.query("UPDATE browser_devices SET body=$2::jsonb WHERE id=$1", {id, device.dump()});
        (void)authorize_device(id, device);
        return profile(id, device);
    }
    if (path == "/api/launcher/devices" && request.method == "GET") {
        auto current = session(db, request, false);
        auto rows = db.query("SELECT id,body FROM browser_devices WHERE account_id=$1 ORDER BY "
                             "(body->'grant'->>'b')::bigint DESC,id LIMIT 64",
                             {text(current, "account", 80)});
        Json devices = Json::array();
        for (int i = 0; i < rows.size(); ++i) {
            auto device = rows.json(i, 1);
            devices.push_back({{"id", rows.at(i, 0)},
                               {"name", device.at("name")},
                               {"created", device.at("grant").at("b")},
                               {"last_used", device.at("last_used")},
                               {"expires_at", device_expiry(device)},
                               {"active", active(device)}});
            devices.back()["client"] =
                device.value("client", client_description(device.value("name", std::string())));
        }
        return {{"devices", devices}};
    }
    if (path == "/api/launcher/revoke" && request.method == "POST") {
        auto current = session(db, request, true);
        auto id = text(body, "id", 32);
        auto rows = db.query("UPDATE browser_devices SET body=jsonb_set(body,'{revoked}','true') WHERE id=$1 "
                             "AND account_id=$2 RETURNING id",
                             {id, text(current, "account", 80)});
        require(rows.size() == 1, "not_found", "设备不存在。", 404);
        (void)admin(db, "/v1/admin/device/revoke",
                    {{"account_id", current.at("account")}, {"device_id", id}});
        return {{"ok", true}};
    }
    if (path == "/api/account/email-code" && request.method == "POST") {
        const auto &settings = browser_smtp_;
        require(smtp_enabled(settings), "mail_unavailable", "邮箱验证服务暂不可用。", 503);
        auto email = lower(text(body, "email", 254));
        require(
            std::regex_match(
                email, std::regex(R"([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")),
            "invalid", "邮箱地址无效。");
        auto purpose = body.value("purpose", std::string("register"));
        require(purpose == "register" || purpose == "login" || purpose == "link" || purpose == "recovery",
                "invalid", "Invalid email purpose");
        std::string nonce, name;
        if (purpose == "register") {
            require(config.registration_open, "forbidden", "此服务暂未开放注册。", 403);
            nonce = text(body, "nonce", 96);
            (void)value(db, "enroll", nonce);
            name = text(body, "username", 32);
            validate_name(name);
        } else if (purpose == "link")
            nonce = text(session(db, request, true), "account", 80);
        else
            nonce = random_id();
        rate(db, sha256(email), 1, 60);
        auto ticket = random_id(), random = unhex(random_id());
        unsigned number = 0;
        for (int i = 0; i < 3; ++i)
            number = (number << 8) | static_cast<unsigned char>(random[std::size_t(i)]);
        auto code = std::to_string(number % 1000000);
        code.insert(0, 6 - code.size(), '0');
        auto mailbox = hmac_sha256(audience_key, std::string("buggcraft-email-v1\0", 19) + email);
        // SMTP is bounded to 12 seconds; retain the email rate row lock until it
        // returns so concurrent sends cannot bypass the mailbox quota.
        db.query("SET LOCAL idle_in_transaction_session_timeout='15s'");
        send_browser_mail(settings, email, code);
        put(db, "mail-ticket", ticket,
            {{"mailbox", mailbox},
             {"code", sha256(code)},
             {"purpose", purpose},
             {"nonce", nonce},
             {"username", lower(name)}},
            600, 256);
        return {{"ticket", ticket}, {"nonce", nonce}, {"expires_in", 600}, {"retry_after", 60}};
    }
    if (path == "/api/account/email-challenge" && request.method == "POST") {
        auto mailbox = verify_mail(proofs.at("mail-ticket"), body, "login", text(body, "nonce", 96));
        auto grant = random_id();
        put(db, "email-grant", grant, {{"mailbox", mailbox}}, 600, 256);
        return {{"grant", grant}, {"accounts", mail_candidates(db, mailbox)}};
    }
    if (path == "/api/account/recovery-verify" && request.method == "POST") {
        auto mailbox = verify_mail(proofs.at("mail-ticket"), body, "recovery", text(body, "nonce", 96));
        auto grant = random_id();
        put(db, "recovery-grant", grant, {{"mailbox", mailbox}}, 600, 256);
        return {{"grant", grant}, {"accounts", mail_candidates(db, mailbox)}};
    }
    if (path == "/api/account/recovery-reset" && request.method == "POST") {
        auto id = text(body, "account", 80);
        const auto &permission = proofs.at("recovery-grant");
        require(db.query("SELECT 1 FROM browser_mailboxes WHERE mailbox=$1 AND account_id=$2",
                         {text(permission, "mailbox", 64), id})
                        .size() == 1,
                "unauthorized", "请选择已验证邮箱绑定的账号。", 401);
        db.lock("browser-recovery:" + id);
        auto rows =
            db.query("SELECT record FROM browser_accounts WHERE id=$1 AND NOT blocked FOR UPDATE", {id});
        require(rows.size() == 1, "unauthorized", "账号暂不可用。", 401);
        auto previous = rows.json(0);
        auto certificate = previous.at("certificate");
        require(certificate.at("home_key") == config.issuer_public, "issuer_unavailable",
                "此账号由另一服务签发，请到原服务重设密码。", 409);
        validate_password(body, text(certificate, "username", 32));
        check_key(body.at("public_key"));
        auto state = body.at("state");
        check_state(state, id, false);
        require(state.at("revision").get<int64_t>() == previous.at("state").at("revision").get<int64_t>() + 1,
                "stale", "账号资料已变更，请重新验证邮箱。", 409);
        check_signature(body.at("public_key"), canonical(state), text(body, "signature", 256));
        certificate["public_key"] = body.at("public_key");
        Json record = {{"certificate", certificate},
                       {"issuer_signature", signature(certificate)},
                       {"state", state},
                       {"signature", body.at("signature")}};
        (void)legacy_identity(certificate, text(record, "issuer_signature", 1024));
        db.query("UPDATE browser_accounts SET record=$2::jsonb WHERE id=$1", {id, record.dump()});
        db.query("UPDATE identities SET public_key=$2 WHERE id=$1", {id, body.at("public_key").dump()});
        db.query("UPDATE devices SET revoked=true WHERE account_id=$1", {id});
        db.query("UPDATE browser_devices SET body=jsonb_set(body,'{revoked}','true') WHERE account_id=$1",
                 {id});
        db.query("DELETE FROM browser_values WHERE body->>'account'=$1 OR body->'grant'->>'a'=$1", {id});
        db.query("UPDATE sessions SET state='offline' WHERE account_id=$1", {id});
        db.query("INSERT INTO audit(action,subject) VALUES('account-recovered',$1)", {id});
        reply.cookie = "account_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/";
        return {{"ok", true}, {"username", certificate.at("username")}};
    }
    if (path == "/api/account/email-accounts" && request.method == "POST") {
        auto current = session(db, request, true);
        auto id = text(current, "account", 80);
        auto mailbox = verify_mail(proofs.at("mail-ticket"), body, "link", id);
        db.query("INSERT INTO browser_mailboxes(mailbox,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
                 {mailbox, id});
        choose_mail(db, mailbox, id);
        return {{"accounts", mail_candidates(db, mailbox)}};
    }
    throw Error(404, "not_found", "Not found");
}
Json Service::import_browser(Database &db, const Json &snapshot) {
    require(config_.browser.has_value(), "config", "Browser identity must be configured");
    require(snapshot.is_object() && snapshot.value("version", 0) == 1 && snapshot.at("accounts").is_array() &&
                snapshot.at("accounts").size() <= 100000 && snapshot.at("devices").is_object() &&
                snapshot.at("devices").size() <= 100000 && snapshot.at("mailboxes").is_array() &&
                snapshot.at("mailboxes").size() <= 200000,
            "invalid", "Invalid identity migration snapshot");
    Transaction transaction(db);
    db.lock("browser:migration");
    require(db.query("SELECT count(*) FROM browser_accounts").number(0) == 0 &&
                db.query("SELECT count(*) FROM browser_devices").number(0) == 0 &&
                db.query("SELECT count(*) FROM browser_mailboxes").number(0) == 0,
            "conflict", "Identity import requires an empty target; existing identities are never overwritten",
            409);
    for (const auto &entry : snapshot.at("accounts")) {
        auto record = entry.at("record");
        const auto &certificate = record.at("certificate");
        auto identity = legacy_identity(certificate, text(record, "issuer_signature", 1024));
        check_state(record.at("state"), identity.first, false);
        check_signature(certificate.at("public_key"), canonical(record.at("state")),
                        text(record, "signature", 256));
        // Old signed routing headers do not participate in unified identity.
        record.erase("routing");
        record.erase("routing_signature");
        db.query(
            "INSERT INTO browser_accounts(id,username,record,blocked) VALUES($1,$2,$3::jsonb,$4::boolean)",
            {identity.first, text(certificate, "username", 32), record.dump(),
             entry.value("blocked", false) ? "true" : "false"});
    }
    for (const auto &[id, device] : snapshot.at("devices").items()) {
        require(std::regex_match(id, std::regex("[0-9a-f]{32}")), "invalid", "Invalid migrated device");
        const auto &grant = device.at("grant");
        auto account_id = text(grant, "a", 80);
        auto rows = db.query("SELECT record FROM browser_accounts WHERE id=$1", {account_id});
        require(rows.size() == 1, "invalid", "Migrated device has no account");
        const auto record = rows.json(0);
        (void)verify_delegation({{"certificate", record.at("certificate")},
                                 {"issuer_signature", record.at("issuer_signature")},
                                 {"device_id", id},
                                 {"device_grant", grant},
                                 {"delegation_signature", device.at("signature")}},
                                false);
        require(device.at("revoked").is_boolean() && device.at("last_used").is_number() &&
                    device.at("last_used").get<double>() > 0,
                "invalid", "Invalid migrated device state");
        (void)text(device, "name", 64);
        db.query("INSERT INTO browser_devices(id,account_id,body) VALUES($1,$2,$3::jsonb)",
                 {id, account_id, device.dump()});
        if (device.at("revoked").get<bool>())
            (void)admin(db, "/v1/admin/device/revoke", {{"account_id", account_id}, {"device_id", id}});
    }
    for (const auto &mail : snapshot.at("mailboxes")) {
        auto hash = text(mail, "mailbox", 64), id = text(mail, "account", 80);
        require(std::regex_match(hash, std::regex("[0-9a-f]{64}")), "invalid", "Invalid mailbox digest");
        db.query("INSERT INTO browser_mailboxes(mailbox,account_id,preferred) VALUES($1,$2,$3::boolean)",
                 {hash, id, mail.value("preferred", false) ? "true" : "false"});
    }
    transaction.commit();
    return {{"accounts", snapshot.at("accounts").size()},
            {"devices", snapshot.at("devices").size()},
            {"mailboxes", snapshot.at("mailboxes").size()}};
}
} // namespace control
