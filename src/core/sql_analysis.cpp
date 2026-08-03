#include "core/sql_analysis.h"

namespace core {

StatementClass statement_class_of(StatementType type) {
    switch (type) {
        case StatementType::Select:
            return StatementClass::Select;
        case StatementType::Insert:
        case StatementType::Update:
        case StatementType::Delete:
            return StatementClass::Dml;
        case StatementType::Create:
        case StatementType::Alter:
        case StatementType::Drop:
            return StatementClass::Ddl;
        case StatementType::Unknown:
            return StatementClass::Unknown;
    }
    return StatementClass::Unknown;
}

const char* to_string(StatementType type) {
    switch (type) {
        case StatementType::Select:
            return "SELECT";
        case StatementType::Insert:
            return "INSERT";
        case StatementType::Update:
            return "UPDATE";
        case StatementType::Delete:
            return "DELETE";
        case StatementType::Create:
            return "CREATE";
        case StatementType::Alter:
            return "ALTER";
        case StatementType::Drop:
            return "DROP";
        case StatementType::Unknown:
            return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* to_string(StatementClass cls) {
    switch (cls) {
        case StatementClass::Select:
            return "SELECT";
        case StatementClass::Dml:
            return "DML";
        case StatementClass::Ddl:
            return "DDL";
        case StatementClass::Unknown:
            return "UNKNOWN";
    }
    return "UNKNOWN";
}

}  // namespace core
