#include "core/data_classification.h"

namespace core {

const char* to_string(PiiCategory category) {
    switch (category) {
        case PiiCategory::Email:
            return "PII.Email";
        case PiiCategory::Phone:
            return "PII.Phone";
        case PiiCategory::CreditCard:
            return "PII.CreditCard";
    }
    return "PII.Unknown";
}

}  // namespace core
