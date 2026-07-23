#include "luck/redact.h"
#include <stdio.h>
#include <string.h>

luck_redaction_options luck_redaction_options_default(void) {
    luck_redaction_options options = {LUCK_REDACT_KEEP_EDGES, 3U, '*'};
    return options;
}

luck_status luck_redact_value(luck_string_view input, const luck_redaction_options *options,
                              char *output, size_t output_capacity) {
    luck_redaction_options defaults;
    size_t index;
    size_t hidden;
    if (output == NULL || output_capacity == 0U || (input.data == NULL && input.length != 0U)) return LUCK_ERROR_INVALID_ARGUMENT;
    defaults = luck_redaction_options_default();
    if (options == NULL) options = &defaults;
    output[0] = '\0';
    switch (options->mode) {
        case LUCK_REDACT_EMPTY: return LUCK_OK;
        case LUCK_REDACT_HASH: {
            int written = snprintf(output, output_capacity, "redacted-%016llx",
                                   (unsigned long long)luck_fnv1a64(input.data, input.length));
            return written < 0 || (size_t)written >= output_capacity ? LUCK_ERROR_BUFFER_TOO_SMALL : LUCK_OK;
        }
        case LUCK_REDACT_FULL:
            hidden = input.length < 4U ? 4U : input.length;
            if (hidden >= output_capacity) return LUCK_ERROR_BUFFER_TOO_SMALL;
            for (index = 0U; index < hidden; index += 1U) output[index] = options->replacement;
            output[hidden] = '\0';
            return LUCK_OK;
        case LUCK_REDACT_KEEP_EDGES:
            if (input.length <= options->visible_edge_bytes * 2U) {
                hidden = input.length < 4U ? 4U : input.length;
                if (hidden >= output_capacity) return LUCK_ERROR_BUFFER_TOO_SMALL;
                for (index = 0U; index < hidden; index += 1U) output[index] = options->replacement;
                output[hidden] = '\0';
                return LUCK_OK;
            }
            hidden = input.length - options->visible_edge_bytes * 2U;
            if (input.length + 1U > output_capacity) return LUCK_ERROR_BUFFER_TOO_SMALL;
            memcpy(output, input.data, options->visible_edge_bytes);
            for (index = 0U; index < hidden; index += 1U) output[options->visible_edge_bytes + index] = options->replacement;
            memcpy(output + options->visible_edge_bytes + hidden,
                   input.data + input.length - options->visible_edge_bytes, options->visible_edge_bytes);
            output[input.length] = '\0';
            return LUCK_OK;
        default: return LUCK_ERROR_UNSUPPORTED;
    }
}

luck_status luck_redact_cookie(luck_cookie *cookie, const luck_redaction_options *options) {
    char replacement[LUCK_COOKIE_VALUE_CAPACITY];
    luck_status status;
    if (cookie == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    status = luck_redact_value(luck_sv(cookie->value), options, replacement, sizeof replacement);
    if (status == LUCK_OK) {
        luck_secure_zero(cookie->value, sizeof cookie->value);
        status = luck_copy_string(cookie->value, sizeof cookie->value, luck_sv(replacement));
    }
    luck_secure_zero(replacement, sizeof replacement);
    return status;
}

void luck_redact_collection(luck_cookie_collection *collection, const luck_redaction_options *options) {
    size_t index;
    if (collection == NULL) return;
    for (index = 0U; index < collection->length; index += 1U) (void)luck_redact_cookie(&collection->items[index], options);
}
