#ifndef LUCK_STRING_H
#define LUCK_STRING_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "luck/status.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct luck_string_view { const char *data; size_t length; } luck_string_view;
luck_string_view luck_sv(const char *text);
luck_string_view luck_sv_n(const char *data, size_t length);
luck_string_view luck_sv_trim(luck_string_view value);
bool luck_sv_equal(luck_string_view left, luck_string_view right);
bool luck_sv_equal_ascii_case(luck_string_view left, luck_string_view right);
bool luck_sv_starts_with(luck_string_view value, luck_string_view prefix);
bool luck_sv_starts_with_ascii_case(luck_string_view value, luck_string_view prefix);
ptrdiff_t luck_sv_find_byte(luck_string_view value, char needle);
ptrdiff_t luck_sv_find(luck_string_view value, luck_string_view needle);
luck_status luck_copy_string(char *destination, size_t capacity, luck_string_view source);
void luck_ascii_lower(char *value);
void luck_secure_zero(void *memory, size_t length);
bool luck_constant_time_equal(const void *left, const void *right, size_t length);
uint64_t luck_fnv1a64(const void *data, size_t length);
#ifdef __cplusplus
}
#endif
#endif
