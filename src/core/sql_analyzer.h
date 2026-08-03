#pragma once

#include <memory>
#include <string>

#include "core/sql_analysis.h"
#include "ports/sql_parser.h"

namespace core {

class SqlAnalyzer {
public:
    // Throws std::invalid_argument if parser is null — fails at construction
    // rather than deferring to a null dereference during analyze().
    explicit SqlAnalyzer(std::unique_ptr<ports::ISqlParser> parser);

    // Never throws (relies on the ISqlParser no-escape contract); every
    // outcome is expressed through SqlAnalysis::status.
    SqlAnalysis analyze(const std::string& sql) const;

private:
    std::unique_ptr<ports::ISqlParser> parser_;
};

}  // namespace core
