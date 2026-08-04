#pragma once

#include <httplib.h>

#include "core/proxy_service.h"

namespace http_adapter {

// The whole POST /query contract, invocable directly with a Request and a
// Response so contract tests need no server thread or socket. Registration
// below is the only thing that requires a live server.
//
// This adapter never sees ports::ExecutionResult — ProxyService returns a
// MaskedQueryResult, so unmasked data cannot reach the wire by construction.
void handle_query_request(core::ProxyService& proxy, const httplib::Request& request,
                          httplib::Response& response);

void register_query_routes(httplib::Server& server, core::ProxyService& proxy);

}  // namespace http_adapter
