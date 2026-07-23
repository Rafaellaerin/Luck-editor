#ifndef LUCK_STATUS_H
#define LUCK_STATUS_H
#ifdef __cplusplus
extern "C" {
#endif
typedef enum luck_status {
    LUCK_OK = 0,
    LUCK_ERROR_INVALID_ARGUMENT = 1,
    LUCK_ERROR_OUT_OF_MEMORY = 2,
    LUCK_ERROR_LIMIT_EXCEEDED = 3,
    LUCK_ERROR_INVALID_COOKIE = 4,
    LUCK_ERROR_PARSE = 5,
    LUCK_ERROR_BUFFER_TOO_SMALL = 6,
    LUCK_ERROR_NOT_FOUND = 7,
    LUCK_ERROR_UNSUPPORTED = 8,
    LUCK_ERROR_INTERNAL = 255
} luck_status;
const char *luck_status_message(luck_status status);
#ifdef __cplusplus
}
#endif
#endif
