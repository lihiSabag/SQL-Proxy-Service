#include "config/database_config.h"

#include <charconv>

namespace config {

namespace {
constexpr int kDefaultStatementTimeoutMs = 5000;
constexpr int kMaxStatementTimeoutMs = 600000;  // 10 minutes; sanity bound
}  // namespace

DatabaseConfigResolution resolve_database_config(const char* database_url,
                                                 const char* statement_timeout_ms) {
    DatabaseConfigResolution out;

    if (database_url == nullptr || std::string(database_url).empty()) {
        out.valid = false;
        out.error = "DATABASE_URL environment variable is required but not set";
        return out;
    }
    out.config.connection_string = database_url;

    if (statement_timeout_ms == nullptr) {
        out.config.statement_timeout_ms = kDefaultStatementTimeoutMs;
        out.valid = true;
        return out;
    }

    std::string raw(statement_timeout_ms);
    if (raw.empty()) {
        out.valid = false;
        out.error = "DB_STATEMENT_TIMEOUT_MS is set but empty";
        return out;
    }

    int parsed = 0;
    const char* begin = raw.data();
    const char* end = raw.data() + raw.size();
    auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc() || result.ptr != end) {
        out.valid = false;
        out.error = "DB_STATEMENT_TIMEOUT_MS is not a valid integer";
        return out;
    }
    if (parsed <= 0 || parsed > kMaxStatementTimeoutMs) {
        out.valid = false;
        out.error = "DB_STATEMENT_TIMEOUT_MS is out of range (1-" +
                    std::to_string(kMaxStatementTimeoutMs) + ")";
        return out;
    }

    out.config.statement_timeout_ms = parsed;
    out.valid = true;
    return out;
}

}  // namespace config
