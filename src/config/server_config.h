#pragma once

#include <cstdint>
#include <string>

namespace config {

enum class PortSource {
    Default,
    Environment,
};

struct PortResolution {
    bool valid;
    uint16_t port;      // meaningful only if valid == true
    PortSource source;  // meaningful only if valid == true
    std::string error;  // meaningful only if valid == false
};

// Pass std::getenv("PORT") directly. nullptr means "unset" -> default_port.
PortResolution resolve_port(const char* port_env_value, uint16_t default_port = 8080);

} // namespace config
