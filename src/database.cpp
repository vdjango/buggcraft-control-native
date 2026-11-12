#include "control/database.hpp"

namespace control {
Rows::Rows(PGresult *result) : result_(result, PQclear) {}
int Rows::size() const {
    return PQntuples(result_.get());
}
std::string Rows::at(int row, int col) const {
    require(row >= 0 && row < size() && col >= 0 && col < PQnfields(result_.get()), "internal",
            "Invalid result access", 500);
    return PQgetisnull(result_.get(), row, col) ? "" : PQgetvalue(result_.get(), row, col);
}
Json Rows::json(int row, int col) const {
    return Json::parse(at(row, col));
}
std::int64_t Rows::number(int row, int col) const {
    return std::stoll(at(row, col));
}
Database::Database(const std::string &conninfo) : connection_(nullptr, PQfinish) {
    const char *keywords[] = {"dbname", "connect_timeout", "application_name", nullptr};
    const char *values[] = {conninfo.c_str(), "3", "buggcraft-control", nullptr};
    connection_.reset(PQconnectdbParams(keywords, values, 1));
    require(connection_ && PQstatus(connection_.get()) == CONNECTION_OK, "storage_unavailable",
            "Database unavailable", 503);
    query("SET statement_timeout='5s'");
    query("SET lock_timeout='2s'");
    query("SET idle_in_transaction_session_timeout='10s'");
}
Rows Database::query(std::string_view sql, const Params &params) {
    std::vector<const char *> values;
    values.reserve(params.size());
    for (const auto &param : params)
        values.push_back(param.c_str());
    std::unique_ptr<PGresult, decltype(&PQclear)> result(
        PQexecParams(connection_.get(), std::string(sql).c_str(), int(values.size()), nullptr, values.data(),
                     nullptr, nullptr, 0),
        PQclear);
    if (!result || (PQresultStatus(result.get()) != PGRES_TUPLES_OK &&
                    PQresultStatus(result.get()) != PGRES_COMMAND_OK)) {
        const char *code = result ? PQresultErrorField(result.get(), PG_DIAG_SQLSTATE) : nullptr;
        if (code && std::string_view(code) == "23505")
            throw Error(409, "conflict", "Conflicting idempotency or identity");
        throw Error(503, "storage_unavailable", "Storage unavailable; retry with the same idempotency key");
    }
    return Rows(result.release());
}
void Database::lock(std::string key) {
    query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", {std::move(key)});
}
void Database::migrate(const std::string &sql) {
    std::unique_ptr<PGresult, decltype(&PQclear)> result(PQexec(connection_.get(), sql.c_str()), PQclear);
    require(result && PQresultStatus(result.get()) == PGRES_COMMAND_OK, "migration",
            "Schema migration failed", 500);
    auto versions = query("SELECT max(version) FROM schema_version");
    require(versions.size() == 1 && versions.number(0) == 1, "migration", "Unsupported schema version", 500);
}
Transaction::Transaction(Database &db) : db_(db) {
    db_.query("BEGIN");
}
Transaction::~Transaction() {
    if (!committed_) {
        try {
            db_.query("ROLLBACK");
        } catch (...) {
        }
    }
}
void Transaction::commit() {
    db_.query("COMMIT");
    committed_ = true;
}
} // namespace control
