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
    src/config/database_config.cpp
    src/core/sql_analysis.cpp
    src/core/sql_analyzer.cpp
    src/core/policy_decision.cpp
    src/core/policy_engine.cpp
    src/core/data_classification.cpp
    src/core/data_classifier.cpp
    src/core/pii_masker.cpp
    src/core/audit_record.cpp
    src/core/service_result.cpp
    src/core/proxy_service.cpp
    src/logging/system_log.cpp
    src/http/http_server.cpp
    src/http/health_routes.cpp
    src/http/query_routes.cpp
    src/parser/hyrise_sql_parser.cpp
    src/postgres/postgres_query_executor.cpp
    src/audit/jsonl_audit_repository.cpp
)

target_include_directories(sql_proxy_service
    PRIVATE
        src
)

target_link_libraries(sql_proxy_service
    PRIVATE
        httplib::httplib
        nlohmann_json::nlohmann_json
        libpqxx::pqxx
        spdlog::spdlog
        hsql_vendored
)

add_executable(sql_proxy_unit_tests
    tests/core/server_config_test.cpp
    tests/core/database_config_test.cpp
    tests/core/sql_analyzer_test.cpp
    tests/core/sql_parser_contract_test.cpp
    tests/core/policy_engine_test.cpp
    tests/core/data_classifier_test.cpp
    tests/core/pii_masker_test.cpp
    tests/core/audit_record_test.cpp
    tests/core/jsonl_audit_repository_test.cpp
    tests/core/proxy_service_test.cpp
    src/config/server_config.cpp
    src/config/database_config.cpp
    src/core/sql_analysis.cpp
    src/core/sql_analyzer.cpp
    src/core/policy_decision.cpp
    src/core/policy_engine.cpp
    src/core/data_classification.cpp
    src/core/data_classifier.cpp
    src/core/pii_masker.cpp
    src/core/audit_record.cpp
    src/core/service_result.cpp
    src/core/proxy_service.cpp
    src/logging/system_log.cpp
    src/parser/hyrise_sql_parser.cpp
    src/audit/jsonl_audit_repository.cpp
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
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        hsql_vendored
)

add_test(NAME sql_proxy_unit_tests COMMAND sql_proxy_unit_tests)
set_tests_properties(sql_proxy_unit_tests PROPERTIES LABELS "unit")

# HTTP contract tests. Separate target because they need no database and must
# not skip when PostgreSQL is absent — folding them into the postgres target
# would make its "postgres" label untrue.
add_executable(sql_proxy_http_tests
    tests/integration/http_query_test.cpp
    src/core/sql_analysis.cpp
    src/core/sql_analyzer.cpp
    src/core/policy_decision.cpp
    src/core/policy_engine.cpp
    src/core/data_classification.cpp
    src/core/data_classifier.cpp
    src/core/pii_masker.cpp
    src/core/audit_record.cpp
    src/core/service_result.cpp
    src/core/proxy_service.cpp
    src/logging/system_log.cpp
    src/http/http_server.cpp
    src/http/health_routes.cpp
    src/http/query_routes.cpp
)

target_include_directories(sql_proxy_http_tests
    PRIVATE
        src
        tests/fakes
)

target_link_libraries(sql_proxy_http_tests
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        httplib::httplib
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)

add_test(NAME sql_proxy_http_tests COMMAND sql_proxy_http_tests)
set_tests_properties(sql_proxy_http_tests PROPERTIES LABELS "integration;http")

# Executor tests against a real PostgreSQL. Kept in a separate target with its
# own label so the unit target stays database-free and never skips.
add_executable(sql_proxy_integration_tests
    tests/integration/postgres_query_executor_test.cpp
    tests/integration/end_to_end_test.cpp
    src/config/database_config.cpp
    src/core/sql_analysis.cpp
    src/core/sql_analyzer.cpp
    src/core/policy_decision.cpp
    src/core/policy_engine.cpp
    src/core/data_classification.cpp
    src/core/data_classifier.cpp
    src/core/pii_masker.cpp
    src/core/audit_record.cpp
    src/core/service_result.cpp
    src/core/proxy_service.cpp
    src/logging/system_log.cpp
    src/parser/hyrise_sql_parser.cpp
    src/postgres/postgres_query_executor.cpp
    src/audit/jsonl_audit_repository.cpp
    src/http/query_routes.cpp
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
        httplib::httplib
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        libpqxx::pqxx
        hsql_vendored
)

add_test(NAME sql_proxy_integration_tests COMMAND sql_proxy_integration_tests)
set_tests_properties(sql_proxy_integration_tests PROPERTIES LABELS "integration;postgres")
