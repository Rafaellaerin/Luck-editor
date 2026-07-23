#include "luck/status.h"
const char *luck_status_message(luck_status status) {
    switch (status) {
        case LUCK_OK: return "ok";
        case LUCK_ERROR_INVALID_ARGUMENT: return "invalid argument";
        case LUCK_ERROR_OUT_OF_MEMORY: return "out of memory";
        case LUCK_ERROR_LIMIT_EXCEEDED: return "limit exceeded";
        case LUCK_ERROR_INVALID_COOKIE: return "invalid cookie";
        case LUCK_ERROR_PARSE: return "parse error";
        case LUCK_ERROR_BUFFER_TOO_SMALL: return "buffer too small";
        case LUCK_ERROR_NOT_FOUND: return "not found";
        case LUCK_ERROR_UNSUPPORTED: return "unsupported operation";
        case LUCK_ERROR_INTERNAL: return "internal error";
        default: return "unknown status";
    }
}
