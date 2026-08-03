#pragma once

#include <memory>

#include <spdlog/spdlog.h>

namespace system_log {

// Must be called once, before logger() is used.
void init();

std::shared_ptr<spdlog::logger> logger();

} // namespace system_log
