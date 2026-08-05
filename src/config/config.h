#pragma once

#include <cstdint>
#include <string>

namespace config {

// Two independent settings groups, kept as separate typed structs: the
// HTTP port and the database connection. Neither is derived from the other.


enum class PortSource {
    Default,
    Environment,
};

struct PortResolution {
    bool valid;
    uint16_t port;      // meaningful only if valid == true
    PortSource source;  // meaningful only if valid == true
    std::string error;  // meaningful only if valid == false
};

// Pass std::getenv("PORT") directly. nullptr means "unset" -> default_port.
PortResolution resolve_port(const char* port_env_value, uint16_t default_port = 8080);


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
