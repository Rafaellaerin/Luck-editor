#include "luck/buffer.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t next_capacity(size_t current, size_t required) {
    size_t candidate = current < 64U ? 64U : current;
    while (candidate < required) {
        if (candidate > SIZE_MAX / 2U) return required;
        candidate *= 2U;
    }
    return candidate;
}

void luck_buffer_init(luck_buffer *buffer) {
    if (buffer != NULL) { buffer->data = NULL; buffer->length = 0U; buffer->capacity = 0U; }
}

void luck_buffer_destroy(luck_buffer *buffer) {
    if (buffer == NULL) return;
    if (buffer->data != NULL) {
        luck_secure_zero(buffer->data, buffer->capacity);
        free(buffer->data);
    }
    luck_buffer_init(buffer);
}

void luck_buffer_clear(luck_buffer *buffer) {
    if (buffer == NULL) return;
    if (buffer->data != NULL) {
        luck_secure_zero(buffer->data, buffer->length);
        buffer->data[0] = '\0';
    }
    buffer->length = 0U;
}

luck_status luck_buffer_reserve(luck_buffer *buffer, size_t minimum_capacity) {
    char *replacement;
    size_t capacity;
    if (buffer == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    if (minimum_capacity <= buffer->capacity) return LUCK_OK;
    capacity = next_capacity(buffer->capacity, minimum_capacity);
    replacement = (char *)realloc(buffer->data, capacity);
    if (replacement == NULL) return LUCK_ERROR_OUT_OF_MEMORY;
    buffer->data = replacement;
    buffer->capacity = capacity;
    if (buffer->length == 0U) buffer->data[0] = '\0';
    return LUCK_OK;
}

luck_status luck_buffer_append(luck_buffer *buffer, luck_string_view value) {
    luck_status status;
    size_t required;
    if (buffer == NULL || (value.data == NULL && value.length != 0U)) return LUCK_ERROR_INVALID_ARGUMENT;
    if (value.length > SIZE_MAX - buffer->length - 1U) return LUCK_ERROR_LIMIT_EXCEEDED;
    required = buffer->length + value.length + 1U;
    status = luck_buffer_reserve(buffer, required);
    if (status != LUCK_OK) return status;
    if (value.length > 0U) {
        memcpy(buffer->data + buffer->length, value.data, value.length);
        buffer->length += value.length;
    }
    buffer->data[buffer->length] = '\0';
    return LUCK_OK;
}

luck_status luck_buffer_append_char(luck_buffer *buffer, char value) { return luck_buffer_append(buffer, luck_sv_n(&value, 1U)); }
luck_status luck_buffer_append_cstr(luck_buffer *buffer, const char *value) { return luck_buffer_append(buffer, luck_sv(value)); }

luck_status luck_buffer_append_json_string(luck_buffer *buffer, luck_string_view value) {
    size_t index;
    luck_status status = luck_buffer_append_char(buffer, '"');
    if (status != LUCK_OK) return status;
    for (index = 0U; index < value.length; index += 1U) {
        const unsigned char byte = (unsigned char)value.data[index];
        const char *escape = NULL;
        switch (byte) {
            case '"': escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default: break;
        }
        if (escape != NULL) status = luck_buffer_append_cstr(buffer, escape);
        else if (byte < 0x20U) {
            char encoded[7];
            int written = snprintf(encoded, sizeof encoded, "\\u%04x", (unsigned int)byte);
            if (written != 6) return LUCK_ERROR_INTERNAL;
            status = luck_buffer_append(buffer, luck_sv_n(encoded, 6U));
        } else status = luck_buffer_append_char(buffer, (char)byte);
        if (status != LUCK_OK) return status;
    }
    return luck_buffer_append_char(buffer, '"');
}
