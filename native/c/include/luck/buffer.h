#ifndef LUCK_BUFFER_H
#define LUCK_BUFFER_H
#include <stddef.h>
#include "luck/status.h"
#include "luck/string.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct luck_buffer { char *data; size_t length; size_t capacity; } luck_buffer;
void luck_buffer_init(luck_buffer *buffer);
void luck_buffer_destroy(luck_buffer *buffer);
void luck_buffer_clear(luck_buffer *buffer);
luck_status luck_buffer_reserve(luck_buffer *buffer, size_t minimum_capacity);
luck_status luck_buffer_append(luck_buffer *buffer, luck_string_view value);
luck_status luck_buffer_append_char(luck_buffer *buffer, char value);
luck_status luck_buffer_append_cstr(luck_buffer *buffer, const char *value);
luck_status luck_buffer_append_json_string(luck_buffer *buffer, luck_string_view value);
#ifdef __cplusplus
}
#endif
#endif
