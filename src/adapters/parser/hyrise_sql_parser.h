#pragma once

#include <string>

#include "ports/sql_parser.h"

namespace parser_adapter {

// Production ISqlParser implementation wrapping hyrise/sql-parser.
//
// All hsql:: types stay inside the .cpp — this header exposes only the port.
// Stateless: one instance is reusable across calls.
class HyriseSqlParser : public ports::ISqlParser {
public:
    ports::ParseResult parse(const std::string& sql) override;
};

}  // namespace parser_adapter
