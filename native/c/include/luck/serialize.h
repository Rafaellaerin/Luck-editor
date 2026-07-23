#ifndef LUCK_SERIALIZE_H
#define LUCK_SERIALIZE_H
#include <stdbool.h>
#include "luck/buffer.h"
#include "luck/cookie.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum luck_output_format {
    LUCK_OUTPUT_JSON = 0, LUCK_OUTPUT_REDACTED_JSON = 1, LUCK_OUTPUT_NETSCAPE = 2,
    LUCK_OUTPUT_COOKIE_HEADER = 3, LUCK_OUTPUT_SET_COOKIE = 4
} luck_output_format;
typedef struct luck_serialize_options { luck_output_format format; bool include_http_only; bool pretty_json; } luck_serialize_options;
luck_serialize_options luck_serialize_options_default(void);
const char *luck_output_format_name(luck_output_format format);
luck_status luck_serialize_cookies(const luck_cookie_collection *collection, const luck_serialize_options *options, luck_buffer *output);
#ifdef __cplusplus
}
#endif
#endif
