#include "adapters/http/http_server.h"

#include "adapters/http/health_routes.h"
#include "logging/system_log.h"

namespace http_adapter {

HttpServer::HttpServer() {
    register_routes();
}

void HttpServer::register_routes() {
    register_health_routes(server_);
}

bool HttpServer::run(uint16_t port) {
    system_log::logger()->info("HTTP server listening on port {}", port);
    return server_.listen("0.0.0.0", port);
}

} // namespace http_adapter
