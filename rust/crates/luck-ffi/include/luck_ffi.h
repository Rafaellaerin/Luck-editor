#ifndef LUCK_FFI_H
#define LUCK_FFI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum LuckStatus {
    LUCK_STATUS_OK = 0,
    LUCK_STATUS_NULL_POINTER = 1,
    LUCK_STATUS_INVALID_UTF8 = 2,
    LUCK_STATUS_PARSE_ERROR = 3,
    LUCK_STATUS_SERIALIZATION_ERROR = 4,
    LUCK_STATUS_PANIC = 255
} LuckStatus;

typedef struct LuckBuffer {
    char *data;
    size_t length;
    LuckStatus status;
} LuckBuffer;

const char *luck_version(void);
LuckBuffer luck_parse_json(const char *input, const char *fallback_domain);
LuckBuffer luck_convert_redacted_json(const char *input, const char *fallback_domain);
void luck_buffer_free(LuckBuffer buffer);

#ifdef __cplusplus
}
#endif

#endif
