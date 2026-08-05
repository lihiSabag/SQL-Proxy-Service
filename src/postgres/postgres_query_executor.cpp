#include "postgres/postgres_query_executor.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <pqxx/pqxx>

// Error-sanitization rule: PostgreSQL error messages
// routinely echo data values (e.g. unique-violation messages), and libpq
// connection errors can echo connection details. ExecutionResult::error is
// therefore built ONLY from fixed literals plus a SQLSTATE code — never from
// driver message text, SQL fragments, or the connection string.

namespace postgres_adapter {

namespace {

// Private OID -> neutral ColumnType map. OIDs never leave this file.
ports::ColumnType column_type_from_oid(unsigned int oid) {
    switch (oid) {
        case 25:    // text
        case 1043:  // varchar
        case 1042:  // bpchar
            return ports::ColumnType::Text;
        case 20:  // int8
        case 21:  // int2
        case 23:  // int4
            return ports::ColumnType::Integer;
        case 700:  // float4
        case 701:  // float8
            return ports::ColumnType::Float;
        case 1700:  // numeric
            return ports::ColumnType::Numeric;
        case 16:  // bool
            return ports::ColumnType::Boolean;
        case 1114:  // timestamp
        case 1184:  // timestamptz
            return ports::ColumnType::Timestamp;
        case 1082:  // date
            return ports::ColumnType::Date;
        default:
            return ports::ColumnType::Other;
    }
}

ports::ExecutionResult translate(const pqxx::result& result) {
    ports::ExecutionResult out;
    out.status = ports::ExecutionStatus::Ok;

    const auto column_count = result.columns();
    out.has_result_set = column_count > 0;

    for (pqxx::row_size_type c = 0; c < column_count; ++c) {
        ports::ColumnInfo column;
        column.name = result.column_name(c);
        column.type = column_type_from_oid(static_cast<unsigned int>(result.column_type(c)));
        out.columns.push_back(std::move(column));
    }

    out.rows.reserve(result.size());
    for (const pqxx::row& row : result) {
        std::vector<std::optional<std::string>> cells;
        cells.reserve(column_count);
        for (pqxx::row_size_type c = 0; c < column_count; ++c) {
            const pqxx::field& field = row[c];
            if (field.is_null()) {
                cells.emplace_back(std::nullopt);
            } else {
                cells.emplace_back(std::string(field.view()));
            }
        }
        out.rows.push_back(std::move(cells));
    }

    out.row_count = static_cast<long long>(result.size());
    out.affected_rows = static_cast<long long>(result.affected_rows());
    return out;
}

ports::ExecutionResult failure(ports::ExecutionStatus status, std::string error) {
    ports::ExecutionResult out;
    out.status = status;
    out.error = std::move(error);
    return out;
}

}  // namespace

PostgresQueryExecutor::PostgresQueryExecutor(config::DatabaseConfig config)
    : config_(std::move(config)) {}

ports::ExecutionResult PostgresQueryExecutor::execute(const std::string& sql) {
    try {
        // One connection and one transaction per call; RAII cleans up every
        // path, and an uncommitted transaction aborts on unwind.
        pqxx::connection connection(config_.connection_string);
        pqxx::work transaction(connection);

        // Scoped to this transaction; dies with it.
        transaction.exec("SET LOCAL statement_timeout = " +
                         std::to_string(config_.statement_timeout_ms));

        pqxx::result result = transaction.exec(sql);
        ports::ExecutionResult out = translate(result);
        transaction.commit();  // only reached on success
        return out;
    } catch (const pqxx::broken_connection&) {
        return failure(ports::ExecutionStatus::ConnectionFailure, "connection failed");
    } catch (const pqxx::sql_error& e) {
        return failure(ports::ExecutionStatus::ExecutionFailure,
                       "statement failed (SQLSTATE " + e.sqlstate() + ")");
    } catch (const pqxx::failure&) {
        return failure(ports::ExecutionStatus::ExecutionFailure, "statement failed");
    } catch (...) {
        // Port contract: no exception escapes the adapter.
        return failure(ports::ExecutionStatus::ExecutionFailure, "executor failure");
    }
}

}  // namespace postgres_adapter
