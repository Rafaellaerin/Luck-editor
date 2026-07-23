#ifndef LUCK_REDACT_H
#define LUCK_REDACT_H
#include <stddef.h>
#include "luck/cookie.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum luck_redaction_mode { LUCK_REDACT_FULL = 0, LUCK_REDACT_KEEP_EDGES = 1, LUCK_REDACT_HASH = 2, LUCK_REDACT_EMPTY = 3 } luck_redaction_mode;
typedef struct luck_redaction_options { luck_redaction_mode mode; size_t visible_edge_bytes; char replacement; } luck_redaction_options;
luck_redaction_options luck_redaction_options_default(void);
luck_status luck_redact_value(luck_string_view input, const luck_redaction_options *options, char *output, size_t output_capacity);
luck_status luck_redact_cookie(luck_cookie *cookie, const luck_redaction_options *options);
void luck_redact_collection(luck_cookie_collection *collection, const luck_redaction_options *options);
#ifdef __cplusplus
}
#endif
#endif
