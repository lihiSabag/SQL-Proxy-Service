#pragma once

#include <string>

#include "ports/sql_parser.h"

namespace fakes {

class FakeSqlParser : public ports::ISqlParser {
public:
    ports::ParseResult result_to_return;
    std::string last_sql_received;
    int parse_call_count = 0;

    ports::ParseResult parse(const std::string& sql) override {
        ++parse_call_count;
        last_sql_received = sql;
        return result_to_return;
    }
};

}  // namespace fakes
