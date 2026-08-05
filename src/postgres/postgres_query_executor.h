#pragma once

#include <string>

#include "config/database_config.h"
#include "ports/query_executor.h"

namespace postgres_adapter {

// Concrete IQueryExecutor implementation over libpqxx.
//
// All pqxx types stay inside the .cpp — this header exposes only the port
// and config. One connection and one transaction per execute() call; no
// shared state beyond the immutable config, so concurrent calls are safe.
class PostgresQueryExecutor : public ports::IQueryExecutor {
public:
    explicit PostgresQueryExecutor(config::DatabaseConfig config);

    ports::ExecutionResult execute(const std::string& sql) override;

private:
    config::DatabaseConfig config_;
};

}  // namespace postgres_adapter
