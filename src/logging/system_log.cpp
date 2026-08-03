#include "logging/system_log.h"

#include <spdlog/sinks/stdout_color_sinks.h>

namespace system_log {

namespace {
std::shared_ptr<spdlog::logger> g_logger;
} // namespace

void init() {
    if (!g_logger) {
        g_logger = spdlog::stdout_color_mt("sql_proxy_service");
        g_logger->set_level(spdlog::level::info);
    }
}

std::shared_ptr<spdlog::logger> logger() {
    return g_logger;
}

} // namespace system_log
