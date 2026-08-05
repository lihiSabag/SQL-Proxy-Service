#include "http/health_routes.h"

#include <nlohmann/json.hpp>

namespace http_adapter {

void register_health_routes(httplib::Server& server) {
    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json body{{"status", "ok"}};
        res.set_content(body.dump(), "application/json");
        res.status = 200;
    });
}

} // namespace http_adapter
