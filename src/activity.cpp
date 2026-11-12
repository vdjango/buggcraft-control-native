#include "control/service.hpp"
#include <algorithm>

namespace control {
void Service::record_activity(Database &db, const std::string &account, const std::string &kind, int lease) {
    // Serialize overlapping device/node heartbeats before reading the clock.
    db.query("INSERT INTO account_activity(account_id,kind,started,last_seen,lease_until) "
             "VALUES($1,$2,0,0,0) ON CONFLICT DO NOTHING",
             {account, kind});
    auto row = db.query(
        "SELECT last_seen,lease_until FROM account_activity WHERE account_id=$1 AND kind=$2 FOR UPDATE",
        {account, kind});
    auto now = db.query("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").number(0);
    auto previous = row.number(0, 0);
    auto delta = previous > 0 && row.number(0, 1) >= now ? std::max<int64_t>(0, now - previous) : 0;
    auto timestamp = std::to_string(now);
    db.query("UPDATE account_activity SET started=CASE WHEN started=0 THEN $3::bigint ELSE started END,"
             "last_seen=$3::bigint,lease_until=$4::bigint,seconds=seconds+$5::bigint WHERE account_id=$1 AND "
             "kind=$2",
             {account, kind, timestamp, std::to_string(now + lease), std::to_string(delta)});
    if (delta > 0) {
        db.query(R"SQL(INSERT INTO account_activity_days(account_id,kind,day,seconds)
            SELECT $1,$2,d::date,
              LEAST($4::bigint,extract(epoch FROM ((d+interval '1 day') AT TIME ZONE 'Asia/Shanghai'))::bigint)
              -GREATEST($3::bigint,extract(epoch FROM (d AT TIME ZONE 'Asia/Shanghai'))::bigint)
            FROM generate_series(date_trunc('day',to_timestamp($3::bigint) AT TIME ZONE 'Asia/Shanghai'),
              date_trunc('day',to_timestamp($4::bigint-1) AT TIME ZONE 'Asia/Shanghai'),interval '1 day') d
            ON CONFLICT(account_id,kind,day) DO UPDATE
            SET seconds=account_activity_days.seconds+excluded.seconds)SQL",
                 {account, kind, std::to_string(now - delta), timestamp});
    }
}

void Service::record_companions(Database &db, const std::string &account, const std::string &room,
                                const std::string &epoch) {
    auto peers = db.query(
        R"SQL(SELECT a.actor,floor(extract(epoch FROM max(a.expires_at)))::bigint FROM reservations a JOIN friendships f
        ON f.low_id=LEAST($1,a.actor) AND f.high_id=GREATEST($1,a.actor) AND f.state='accepted'
        WHERE a.room_id=$2 AND a.room_epoch=$3::bigint AND a.actor<>$1 AND a.state='active'
        AND a.expires_at>clock_timestamp() GROUP BY a.actor ORDER BY a.actor LIMIT 32)SQL",
        {account, room, epoch});
    for (int i = 0; i < peers.size(); ++i) {
        db.query(R"SQL(INSERT INTO companion_activity(low_id,high_id,started,last_seen)
            VALUES(LEAST($1,$2),GREATEST($1,$2),floor(extract(epoch FROM clock_timestamp()))::bigint,
            floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT DO NOTHING)SQL",
                 {account, peers.at(i, 0)});
        db.query(R"SQL(UPDATE companion_activity SET
            seconds=seconds+CASE WHEN floor(extract(epoch FROM clock_timestamp()))::bigint-last_seen BETWEEN 0 AND 120
            AND room_id=$3 AND room_epoch=$4::bigint AND lease_until>=floor(extract(epoch FROM clock_timestamp()))::bigint
            THEN floor(extract(epoch FROM clock_timestamp()))::bigint-last_seen ELSE 0 END,
            last_seen=floor(extract(epoch FROM clock_timestamp()))::bigint,
            room_id=$3,room_epoch=$4::bigint,
            lease_until=LEAST($5::bigint,floor(extract(epoch FROM clock_timestamp()))::bigint+120)
            WHERE low_id=LEAST($1,$2) AND high_id=GREATEST($1,$2))SQL",
                 {account, peers.at(i, 0), room, epoch, peers.at(i, 1)});
    }
}

Json Service::activity(Database &db, const std::string &account) {
    auto totals = db.query("SELECT kind,started,last_seen,seconds FROM account_activity WHERE account_id=$1",
                           {account});
    Json result = {{"online_seconds", 0},
                   {"multiplayer_seconds", 0},
                   {"recording_since", nullptr},
                   {"days", Json::array()},
                   {"companions", Json::array()},
                   {"timezone", "Asia/Shanghai"},
                   {"metric", "confirmed_connection_heartbeats"}};
    int64_t since = INT64_MAX;
    for (int i = 0; i < totals.size(); ++i) {
        result[totals.at(i, 0) + "_seconds"] = totals.number(i, 3);
        if (totals.number(i, 1) > 0)
            since = std::min(since, totals.number(i, 1));
    }
    if (since != INT64_MAX)
        result["recording_since"] = since;
    auto days = db.query(R"SQL(SELECT day::text,coalesce(sum(seconds) FILTER(WHERE kind='online'),0)::bigint,
        coalesce(sum(seconds) FILTER(WHERE kind='multiplayer'),0)::bigint FROM account_activity_days
        WHERE account_id=$1 AND day>=(clock_timestamp() AT TIME ZONE 'Asia/Shanghai')::date-29
        GROUP BY day ORDER BY day)SQL",
                         {account});
    for (int i = 0; i < days.size(); ++i)
        result["days"].push_back({{"day", days.at(i, 0)},
                                  {"online_seconds", days.number(i, 1)},
                                  {"multiplayer_seconds", days.number(i, 2)}});
    auto count = db.query(
        "SELECT count(*) FROM friendships WHERE (low_id=$1 OR high_id=$1) AND state='accepted'", {account});
    result["friends_count"] = count.number(0);
    auto friends = db.query(
        R"SQL(SELECT coalesce(i.username,''),coalesce(c.started,0),coalesce(c.last_seen,0),coalesce(c.seconds,0)
        FROM friendships f JOIN identities i ON i.id=CASE WHEN f.low_id=$1 THEN f.high_id ELSE f.low_id END
        LEFT JOIN companion_activity c ON c.low_id=f.low_id AND c.high_id=f.high_id
        WHERE (f.low_id=$1 OR f.high_id=$1) AND f.state='accepted'
        ORDER BY coalesce(c.last_seen,0) DESC,i.username LIMIT 64)SQL",
        {account});
    for (int i = 0; i < friends.size(); ++i)
        result["companions"].push_back({{"name", friends.at(i, 0)},
                                        {"first_connected", friends.number(i, 1)},
                                        {"last_connected", friends.number(i, 2)},
                                        {"seconds", friends.number(i, 3)}});
    return result;
}
} // namespace control
