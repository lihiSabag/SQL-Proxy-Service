#pragma once

#include <cstdint>
#include <httplib.h>

#include "core/proxy_service.h"

namespace http_adapter {

class HttpServer {
public:
    // The service is referenced, not owned; the caller keeps it alive for
    // the server's lifetime.
    explicit HttpServer(core::ProxyService& proxy);

    // Blocks while listening on the given port.
    // Returns true if listen() exited cleanly, false if it failed to bind.
    bool run(uint16_t port);

    // Stops a running server so a blocked run() returns (used by tests).
    void stop();

private:
    httplib::Server server_;
    core::ProxyService& proxy_;

    void register_routes();
};

} // namespace http_adapter
