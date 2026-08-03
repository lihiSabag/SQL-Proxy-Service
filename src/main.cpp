#include <cstdlib>

#include "adapters/http/http_server.h"
#include "config/server_config.h"
#include "logging/system_log.h"

int main() {
    system_log::init();

    config::PortResolution port_resolution = config::resolve_port(std::getenv("PORT"));

    if (!port_resolution.valid) {
        system_log::logger()->error("Startup failed: {}", port_resolution.error);
        return 1;
    }

    system_log::logger()->info(
        "Starting sql-proxy-service (port source: {})",
        port_resolution.source == config::PortSource::Environment ? "PORT env var" : "default");

    http_adapter::HttpServer server;
    bool clean_exit = server.run(port_resolution.port);

    if (!clean_exit) {
        system_log::logger()->error("HTTP server failed to bind to port {}", port_resolution.port);
        return 1;
    }

    return 0;
}
