#pragma once

#include <httplib.h>

#include "core/proxy_service.h"

namespace http_adapter {

// All service routes.
//
// The POST /query contract is invocable directly with a Request and a
// Response, so contract tests need no server thread or socket. Only
// registration requires a live server.
//
// This adapter never sees ports::ExecutionResult: ProxyService returns a
// MaskedQueryResult, so unmasked data cannot reach the wire.
void handle_query_request(core::ProxyService& proxy, const httplib::Request& request,
                          httplib::Response& response);

void register_query_routes(httplib::Server& server, core::ProxyService& proxy);

void register_health_routes(httplib::Server& server);

}  // namespace http_adapter
