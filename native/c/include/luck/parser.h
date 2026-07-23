#ifndef LUCK_PARSER_H
#define LUCK_PARSER_H
#include <stddef.h>
#include "luck/cookie.h"
#include "luck/validate.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum luck_input_format {
    LUCK_INPUT_AUTO = 0, LUCK_INPUT_COOKIE_HEADER = 1, LUCK_INPUT_SET_COOKIE = 2,
    LUCK_INPUT_LINES = 3, LUCK_INPUT_NETSCAPE = 4
} luck_input_format;
typedef struct luck_parse_options {
    luck_input_format format; const char *fallback_domain; size_t maximum_input_bytes;
    size_t maximum_cookies; bool reject_invalid; bool deduplicate; luck_validation_config validation;
} luck_parse_options;
typedef struct luck_parse_report {
    luck_input_format format; size_t parsed; size_t rejected; size_t warnings;
    size_t duplicates_removed; size_t first_error_line; char message[256];
} luck_parse_report;
luck_parse_options luck_parse_options_default(void);
luck_input_format luck_detect_input_format(luck_string_view input);
const char *luck_input_format_name(luck_input_format format);
luck_status luck_parse_cookies(luck_string_view input, const luck_parse_options *options,
                               luck_cookie_collection *output, luck_parse_report *report);
#ifdef __cplusplus
}
#endif
#endif
