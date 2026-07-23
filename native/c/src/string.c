#include "luck/string.h"
#include <ctype.h>
#include <string.h>

luck_string_view luck_sv(const char *text) {
    return text == NULL ? luck_sv_n(NULL, 0U) : luck_sv_n(text, strlen(text));
}

luck_string_view luck_sv_n(const char *data, size_t length) {
    luck_string_view value = {data, data == NULL ? 0U : length};
    return value;
}

luck_string_view luck_sv_trim(luck_string_view value) {
    size_t start = 0U;
    size_t end = value.length;
    while (start < end && isspace((unsigned char)value.data[start]) != 0) start += 1U;
    while (end > start && isspace((unsigned char)value.data[end - 1U]) != 0) end -= 1U;
    return luck_sv_n(value.data == NULL ? NULL : value.data + start, end - start);
}

bool luck_sv_equal(luck_string_view left, luck_string_view right) {
    return left.length == right.length && (left.length == 0U || memcmp(left.data, right.data, left.length) == 0);
}

bool luck_sv_equal_ascii_case(luck_string_view left, luck_string_view right) {
    size_t index;
    if (left.length != right.length) return false;
    for (index = 0U; index < left.length; index += 1U) {
        if (tolower((unsigned char)left.data[index]) != tolower((unsigned char)right.data[index])) return false;
    }
    return true;
}

bool luck_sv_starts_with(luck_string_view value, luck_string_view prefix) {
    return value.length >= prefix.length && luck_sv_equal(luck_sv_n(value.data, prefix.length), prefix);
}

bool luck_sv_starts_with_ascii_case(luck_string_view value, luck_string_view prefix) {
    return value.length >= prefix.length && luck_sv_equal_ascii_case(luck_sv_n(value.data, prefix.length), prefix);
}

ptrdiff_t luck_sv_find_byte(luck_string_view value, char needle) {
    size_t index;
    for (index = 0U; index < value.length; index += 1U) if (value.data[index] == needle) return (ptrdiff_t)index;
    return -1;
}

ptrdiff_t luck_sv_find(luck_string_view value, luck_string_view needle) {
    size_t index;
    if (needle.length == 0U) return 0;
    if (value.length < needle.length) return -1;
    for (index = 0U; index <= value.length - needle.length; index += 1U) {
        if (memcmp(value.data + index, needle.data, needle.length) == 0) return (ptrdiff_t)index;
    }
    return -1;
}

luck_status luck_copy_string(char *destination, size_t capacity, luck_string_view source) {
    if (destination == NULL || capacity == 0U || (source.data == NULL && source.length != 0U)) return LUCK_ERROR_INVALID_ARGUMENT;
    if (source.length >= capacity) {
        destination[0] = '\0';
        return LUCK_ERROR_BUFFER_TOO_SMALL;
    }
    if (source.length > 0U) memcpy(destination, source.data, source.length);
    destination[source.length] = '\0';
    return LUCK_OK;
}

void luck_ascii_lower(char *value) {
    if (value == NULL) return;
    while (*value != '\0') {
        *value = (char)tolower((unsigned char)*value);
        value += 1;
    }
}

void luck_secure_zero(void *memory, size_t length) {
    volatile unsigned char *cursor = (volatile unsigned char *)memory;
    size_t index;
    if (memory == NULL) return;
    for (index = 0U; index < length; index += 1U) cursor[index] = 0U;
}

bool luck_constant_time_equal(const void *left, const void *right, size_t length) {
    const unsigned char *a = (const unsigned char *)left;
    const unsigned char *b = (const unsigned char *)right;
    unsigned char difference = 0U;
    size_t index;
    if ((left == NULL || right == NULL) && length != 0U) return false;
    for (index = 0U; index < length; index += 1U) difference = (unsigned char)(difference | (unsigned char)(a[index] ^ b[index]));
    return difference == 0U;
}

uint64_t luck_fnv1a64(const void *data, size_t length) {
    const unsigned char *bytes = (const unsigned char *)data;
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t index;
    if (data == NULL) return hash;
    for (index = 0U; index < length; index += 1U) {
        hash ^= (uint64_t)bytes[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}
