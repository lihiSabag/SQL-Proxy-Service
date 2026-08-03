#pragma once

#include <cstdint>
#include <httplib.h>

namespace http_adapter {

class HttpServer {
public:
    HttpServer();

    // Blocks while listening on the given port.
    // Returns true if listen() exited cleanly, false if it failed to bind.
    bool run(uint16_t port);

private:
    httplib::Server server_;

    void register_routes();
};

} // namespace http_adapter
