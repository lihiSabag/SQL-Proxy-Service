#include "core/policy_decision.h"

namespace core {

const char* to_string(RejectReason reason) {
    switch (reason) {
        case RejectReason::NotEvaluated:
            return "NOT_EVALUATED";
        case RejectReason::None:
            return "NONE";
        case RejectReason::EmptyInput:
            return "EMPTY_INPUT";
        case RejectReason::UnparseableSql:
            return "UNPARSEABLE_SQL";
        case RejectReason::MultipleStatements:
            return "MULTIPLE_STATEMENTS";
        case RejectReason::UnsupportedStatementType:
            return "UNSUPPORTED_STATEMENT_TYPE";
        case RejectReason::UnsupportedSqlFeature:
            return "UNSUPPORTED_SQL_FEATURE";
        case RejectReason::DdlNotAllowed:
            return "DDL_NOT_ALLOWED";
        case RejectReason::DmlNotAllowed:
            return "DML_NOT_ALLOWED";
        case RejectReason::SystemTableAccess:
            return "SYSTEM_TABLE_ACCESS";
        case RejectReason::UnattributableProjection:
            return "UNATTRIBUTABLE_PROJECTION";
        case RejectReason::InsertTargetNotAllowed:
            return "INSERT_TARGET_NOT_ALLOWED";
        case RejectReason::UnsupportedInsertShape:
            return "UNSUPPORTED_INSERT_SHAPE";
    }
    return "NOT_EVALUATED";
}

}  // namespace core
