#pragma once

#include <string>

namespace config {

// The connection string may embed credentials. It is a SECRET:
// - never log it (in whole or in part);
// - never include it (or anything derived from it) in returned errors;
// - never print it in test output;
// - never copy it into audit records.
// Error messages produced here reference environment-variable NAMES only,
// never their values.
struct DatabaseConfig {
    std::string connection_string;
    int statement_timeout_ms = 5000;
};

struct DatabaseConfigResolution {
    bool valid = false;
    DatabaseConfig config;  // meaningful only if valid == true
    std::string error;      // meaningful only if valid == false; never contains values
};

// Pass std::getenv("DATABASE_URL") and std::getenv("DB_STATEMENT_TIMEOUT_MS")
// directly. The URL is required (no silent default for a database). The
// timeout defaults to 5000 ms when unset and must be a positive integer.
DatabaseConfigResolution resolve_database_config(const char* database_url,
                                                 const char* statement_timeout_ms);

}  // namespace config
