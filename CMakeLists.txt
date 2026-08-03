cmake_minimum_required(VERSION 3.21)

project(sql_proxy_service LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

enable_testing()

add_executable(sql_proxy_service
    src/main.cpp
    src/config/server_config.cpp
    src/logging/system_log.cpp
    src/adapters/http/http_server.cpp
    src/adapters/http/health_routes.cpp
)

target_include_directories(sql_proxy_service
    PRIVATE
        src
)

target_link_libraries(sql_proxy_service
    PRIVATE
        httplib::httplib
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)

add_executable(sql_proxy_unit_tests
    tests/core/server_config_test.cpp
    src/config/server_config.cpp
)

target_include_directories(sql_proxy_unit_tests
    PRIVATE
        src
)

target_link_libraries(sql_proxy_unit_tests
    PRIVATE
        GTest::gtest
        GTest::gtest_main
)

add_test(NAME sql_proxy_unit_tests COMMAND sql_proxy_unit_tests)
set_tests_properties(sql_proxy_unit_tests PROPERTIES LABELS "unit")
