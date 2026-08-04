cmake_minimum_required(VERSION 3.21)

project(sql_proxy_service LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(libpqxx CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

# hyrise/sql-parser is fetched at a pinned commit. Upstream ships no
# CMakeLists.txt, so the library target is declared here over its sources.
# bison_parser.cpp / flex_lexer.cpp are pre-generated and committed upstream —
# no bison/flex needed to build this.
include(FetchContent)
FetchContent_Declare(
    hyrise_sql_parser
    GIT_REPOSITORY https://github.com/hyrise/sql-parser.git
    GIT_TAG        ccd3f68b50bb2b96ce69afa7b956b3bd826643cc
)
FetchContent_MakeAvailable(hyrise_sql_parser)

set(HSQL_SRC ${hyrise_sql_parser_SOURCE_DIR}/src)

add_library(hsql_vendored STATIC
    ${HSQL_SRC}/SQLParser.cpp
    ${HSQL_SRC}/SQLParserResult.cpp
    ${HSQL_SRC}/parser/bison_parser.cpp
    ${HSQL_SRC}/parser/flex_lexer.cpp
    ${HSQL_SRC}/sql/CreateStatement.cpp
    ${HSQL_SRC}/sql/Expr.cpp
    ${HSQL_SRC}/sql/PrepareStatement.cpp
    ${HSQL_SRC}/sql/SQLStatement.cpp
    ${HSQL_SRC}/sql/statements.cpp
    ${HSQL_SRC}/util/sqlhelper.cpp
)
target_include_directories(hsql_vendored SYSTEM PUBLIC ${HSQL_SRC})
target_compile_options(hsql_vendored PRIVATE -w)

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
    tests/core/database_config_test.cpp
    tests/core/sql_analyzer_test.cpp
    tests/core/sql_parser_contract_test.cpp
    tests/core/policy_engine_test.cpp
    src/config/server_config.cpp
    src/config/database_config.cpp
    src/core/sql_analysis.cpp
    src/core/sql_analyzer.cpp
    src/core/policy_decision.cpp
    src/core/policy_engine.cpp
    src/adapters/parser/hyrise_sql_parser.cpp
)

target_include_directories(sql_proxy_unit_tests
    PRIVATE
        src
        tests/fakes
)

target_link_libraries(sql_proxy_unit_tests
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        hsql_vendored
)

add_test(NAME sql_proxy_unit_tests COMMAND sql_proxy_unit_tests)
set_tests_properties(sql_proxy_unit_tests PROPERTIES LABELS "unit")

# Executor tests against a real PostgreSQL. Kept in a separate target with its
# own label so the unit target stays database-free and never skips.
add_executable(sql_proxy_integration_tests
    tests/integration/postgres_query_executor_test.cpp
    src/config/database_config.cpp
    src/adapters/postgres/postgres_query_executor.cpp
)

target_include_directories(sql_proxy_integration_tests
    PRIVATE
        src
)

# Lets the test fixture locate schema.sql / seed.sql in the source tree.
target_compile_definitions(sql_proxy_integration_tests
    PRIVATE
        SQL_PROXY_SQL_DIR="${CMAKE_CURRENT_SOURCE_DIR}/sql"
)

target_link_libraries(sql_proxy_integration_tests
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        libpqxx::pqxx
)

add_test(NAME sql_proxy_integration_tests COMMAND sql_proxy_integration_tests)
set_tests_properties(sql_proxy_integration_tests PROPERTIES LABELS "integration;postgres")
