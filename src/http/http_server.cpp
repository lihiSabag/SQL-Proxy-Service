#include "http/http_server.h"

#include "http/health_routes.h"
#include "http/query_routes.h"
#include "logging/system_log.h"

namespace http_adapter {

HttpServer::HttpServer(core::ProxyService& proxy) : proxy_(proxy) {
    register_routes();
}

void HttpServer::register_routes() {
    register_health_routes(server_);
    register_query_routes(server_, proxy_);
}

bool HttpServer::run(uint16_t port) {
    system_log::logger()->info("HTTP server listening on port {}", port);
    return server_.listen("0.0.0.0", port);
}

void HttpServer::stop() {
    server_.stop();
}

} // namespace http_adapter
