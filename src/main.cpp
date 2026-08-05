// Process entry point. It reads configuration from the environment, builds the
// concrete components, and hands them to the HTTP server. All the request
// logic lives in ProxyService and the adapters, so this file only wires things
// together and decides when to exit with a failure code.

#include <cstdlib>
#include <memory>
#include <string>

#include "audit/jsonl_audit_repository.h"
#include "http/http_server.h"
#include "parser/hyrise_sql_parser.h"
#include "postgres/postgres_query_executor.h"
#include "config/database_config.h"
#include "config/server_config.h"
#include "core/proxy_service.h"
#include "core/sql_analyzer.h"
#include "logging/system_log.h"

namespace {

// The audit path is the one setting that cannot fail to resolve: an unset or
// empty value falls back to this file rather than stopping startup.
constexpr const char* kDefaultAuditLogPath = "audit.jsonl";

std::string resolve_audit_log_path() {
    const char* configured = std::getenv("AUDIT_LOG_PATH");
    if (configured != nullptr && *configured != '\0') {
        return configured;
    }
    return kDefaultAuditLogPath;
}

}  // namespace

int main() {
    // Logging is set up first so that configuration errors can be reported.
    system_log::init();

    // PORT is optional and falls back to a default.
    config::PortResolution port_resolution = config::resolve_port(std::getenv("PORT"));

    if (!port_resolution.valid) {
        system_log::logger()->error("Startup failed: {}", port_resolution.error);
        return 1;
    }

    // DATABASE_URL is required; the statement timeout has a default.
    // Errors name environment variables, never their values.
    config::DatabaseConfigResolution database_resolution = config::resolve_database_config(
        std::getenv("DATABASE_URL"), std::getenv("DB_STATEMENT_TIMEOUT_MS"));

    if (!database_resolution.valid) {
        system_log::logger()->error("Startup failed: {}", database_resolution.error);
        return 1;
    }

    system_log::logger()->info(
        "Starting sql-proxy-service (port source: {})",
        port_resolution.source == config::PortSource::Environment ? "PORT env var" : "default");

    // The only place the concrete adapters are chosen. Each one is created
    // here and passed in by reference, so the core keeps depending on its
    // interfaces and every component stays alive for as long as the server.
    core::SqlAnalyzer analyzer(std::make_unique<parser_adapter::HyriseSqlParser>());
    postgres_adapter::PostgresQueryExecutor executor(database_resolution.config);
    audit_adapter::JsonlAuditRepository audit(resolve_audit_log_path());
    core::ProxyService proxy(analyzer, executor, audit);

    // Blocks until the process is stopped, or returns false if the port could
    // not be bound.
    http_adapter::HttpServer server(proxy);
    bool clean_exit = server.run(port_resolution.port);

    if (!clean_exit) {
        system_log::logger()->error("HTTP server failed to bind to port {}", port_resolution.port);
        return 1;
    }

    return 0;
}
