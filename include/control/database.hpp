#pragma once
#include "types.hpp"
#include <libpq-fe.h>
#include <memory>
#include <vector>

namespace control {
using Params = std::vector<std::string>;
class Rows {
    std::shared_ptr<PGresult> result_;

  public:
    explicit Rows(PGresult *result);
    int size() const;
    std::string at(int row, int col) const;
    Json json(int row, int col = 0) const;
    std::int64_t number(int row, int col = 0) const;
};
// One connection per bounded worker, never shared concurrently or used on an I/O thread.
class Database {
    using Connection = std::unique_ptr<PGconn, decltype(&PQfinish)>;
    Connection connection_;

  public:
    explicit Database(const std::string &conninfo);
    Rows query(std::string_view sql, const Params &params = Params());
    void lock(std::string key);
    void migrate(const std::string &sql);
};
class Transaction {
    Database &db_;
    bool committed_ = false;

  public:
    explicit Transaction(Database &db);
    ~Transaction();
    void commit();
};
} // namespace control
