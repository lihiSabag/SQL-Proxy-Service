#pragma once

#include <httplib.h>

namespace http_adapter {

void register_health_routes(httplib::Server& server);

} // namespace http_adapter
