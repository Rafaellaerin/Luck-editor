#ifndef LUCK_VALIDATE_H
#define LUCK_VALIDATE_H
#include <stdbool.h>
#include <stddef.h>
#include "luck/cookie.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LUCK_MAX_VALIDATION_ISSUES 32U
#define LUCK_VALIDATION_MESSAGE_CAPACITY 192U
typedef enum luck_issue_severity { LUCK_ISSUE_WARNING = 0, LUCK_ISSUE_ERROR = 1 } luck_issue_severity;
typedef struct luck_validation_issue {
    char code[48]; char field[32]; char message[LUCK_VALIDATION_MESSAGE_CAPACITY]; luck_issue_severity severity;
} luck_validation_issue;
typedef struct luck_validation_report { luck_validation_issue issues[LUCK_MAX_VALIDATION_ISSUES]; size_t length; size_t dropped; } luck_validation_report;
typedef struct luck_validation_config {
    size_t maximum_name_bytes; size_t maximum_value_bytes; size_t maximum_domain_bytes;
    size_t maximum_path_bytes; size_t maximum_total_bytes;
    bool require_domain; bool require_secure_for_none; bool require_secure_for_partitioned;
    bool warn_single_label_domain; bool reject_control_characters;
} luck_validation_config;
luck_validation_config luck_validation_config_default(void);
void luck_validation_report_init(luck_validation_report *report);
bool luck_validation_report_is_valid(const luck_validation_report *report);
size_t luck_validation_error_count(const luck_validation_report *report);
size_t luck_validation_warning_count(const luck_validation_report *report);
luck_status luck_validate_cookie(const luck_cookie *cookie, const luck_validation_config *config, luck_validation_report *report);
bool luck_is_valid_domain(luck_string_view domain);
bool luck_is_valid_cookie_name(luck_string_view name);
#ifdef __cplusplus
}
#endif
#endif
