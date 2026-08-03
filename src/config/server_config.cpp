#include "config/server_config.h"

#include <charconv>

namespace config {

namespace {
constexpr uint16_t kMinPort = 1;
constexpr uint16_t kMaxPort = 65535;
} // namespace

PortResolution resolve_port(const char* port_env_value, uint16_t default_port) {
    if (port_env_value == nullptr) {
        return PortResolution{true, default_port, PortSource::Default, {}};
    }

    std::string raw(port_env_value);

    if (raw.empty()) {
        return PortResolution{false, 0, PortSource::Environment,
                               "PORT environment variable is set but empty"};
    }

    int parsed = 0;
    const char* begin = raw.data();
    const char* end = raw.data() + raw.size();
    auto result = std::from_chars(begin, end, parsed);

    if (result.ec != std::errc() || result.ptr != end) {
        return PortResolution{false, 0, PortSource::Environment,
                               "PORT value '" + raw + "' is not a valid integer"};
    }

    if (parsed < kMinPort || parsed > kMaxPort) {
        return PortResolution{false, 0, PortSource::Environment,
                               "PORT value '" + raw + "' is out of range (" +
                                   std::to_string(kMinPort) + "-" + std::to_string(kMaxPort) + ")"};
    }

    return PortResolution{true, static_cast<uint16_t>(parsed), PortSource::Environment, {}};
}

} // namespace config
