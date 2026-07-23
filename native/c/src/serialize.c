#include "luck/serialize.h"
#include <math.h>
#include <stdio.h>

static luck_status append_indent(luck_buffer *output, unsigned int level) {
    unsigned int index;
    for (index = 0U; index < level; index += 1U) {
        luck_status status = luck_buffer_append_cstr(output, "  ");
        if (status != LUCK_OK) return status;
    }
    return LUCK_OK;
}

static luck_status append_json_key(luck_buffer *output, const char *key, bool pretty, unsigned int indent) {
    luck_status status;
    if (pretty) {
        status = append_indent(output, indent);
        if (status != LUCK_OK) return status;
    }
    status = luck_buffer_append_json_string(output, luck_sv(key));
    if (status != LUCK_OK) return status;
    return luck_buffer_append_cstr(output, pretty ? ": " : ":");
}

static luck_status append_json_cookie(luck_buffer *output, const luck_cookie *cookie, bool redacted, bool pretty) {
    luck_status status;
    const char *newline = pretty ? "\n" : "";
    const char *separator = pretty ? ",\n" : ",";
    status = luck_buffer_append_char(output, '{'); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, newline); if (status != LUCK_OK) return status;
    status = append_json_key(output, "name", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_json_string(output, luck_sv(cookie->name)); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "value", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_json_string(output, luck_sv(redacted ? "[REDACTED]" : cookie->value)); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "domain", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_json_string(output, luck_sv(cookie->domain)); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "path", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_json_string(output, luck_sv(cookie->path)); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "secure", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, cookie->secure ? "true" : "false"); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "httpOnly", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, cookie->http_only ? "true" : "false"); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "sameSite", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_json_string(output, luck_sv(luck_same_site_name(cookie->same_site))); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
    status = append_json_key(output, "session", pretty, 2U); if (status != LUCK_OK) return status;
    status = luck_buffer_append_cstr(output, cookie->session ? "true" : "false"); if (status != LUCK_OK) return status;
    if (!cookie->session && cookie->expiration_date > 0.0) {
        char number[64];
        int written;
        status = luck_buffer_append_cstr(output, separator); if (status != LUCK_OK) return status;
        status = append_json_key(output, "expirationDate", pretty, 2U); if (status != LUCK_OK) return status;
        written = snprintf(number, sizeof number, "%.0f", floor(cookie->expiration_date));
        if (written < 0 || (size_t)written >= sizeof number) return LUCK_ERROR_INTERNAL;
        status = luck_buffer_append(output, luck_sv_n(number, (size_t)written)); if (status != LUCK_OK) return status;
    }
    status = luck_buffer_append_cstr(output, newline); if (status != LUCK_OK) return status;
    if (pretty) { status = append_indent(output, 1U); if (status != LUCK_OK) return status; }
    return luck_buffer_append_char(output, '}');
}

static luck_status serialize_json(const luck_cookie_collection *collection, const luck_serialize_options *options,
                                  luck_buffer *output, bool redacted) {
    size_t index;
    bool first = true;
    luck_status status = luck_buffer_append_cstr(output, options->pretty_json ? "[\n" : "[");
    if (status != LUCK_OK) return status;
    for (index = 0U; index < collection->length; index += 1U) {
        const luck_cookie *cookie = &collection->items[index];
        if (!options->include_http_only && cookie->http_only) continue;
        if (!first) { status = luck_buffer_append_cstr(output, options->pretty_json ? ",\n" : ","); if (status != LUCK_OK) return status; }
        first = false;
        if (options->pretty_json) { status = append_indent(output, 1U); if (status != LUCK_OK) return status; }
        status = append_json_cookie(output, cookie, redacted, options->pretty_json);
        if (status != LUCK_OK) return status;
    }
    return luck_buffer_append_cstr(output, options->pretty_json ? "\n]\n" : "]");
}

static luck_status serialize_header(const luck_cookie_collection *collection, const luck_serialize_options *options,
                                    luck_buffer *output) {
    size_t index;
    bool first = true;
    luck_status status = luck_buffer_append_cstr(output, "Cookie: ");
    if (status != LUCK_OK) return status;
    for (index = 0U; index < collection->length; index += 1U) {
        const luck_cookie *cookie = &collection->items[index];
        if (!options->include_http_only && cookie->http_only) continue;
        if (!first) { status = luck_buffer_append_cstr(output, "; "); if (status != LUCK_OK) return status; }
        first = false;
        status = luck_buffer_append_cstr(output, cookie->name); if (status != LUCK_OK) return status;
        status = luck_buffer_append_char(output, '='); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->value); if (status != LUCK_OK) return status;
    }
    return LUCK_OK;
}

static luck_status serialize_netscape(const luck_cookie_collection *collection, const luck_serialize_options *options,
                                      luck_buffer *output) {
    size_t index;
    luck_status status = luck_buffer_append_cstr(output, "# Netscape HTTP Cookie File\n# Generated by Luck Editor native core\n\n");
    if (status != LUCK_OK) return status;
    for (index = 0U; index < collection->length; index += 1U) {
        const luck_cookie *cookie = &collection->items[index];
        char expiration[64];
        int written;
        if (!options->include_http_only && cookie->http_only) continue;
        if (cookie->http_only) { status = luck_buffer_append_cstr(output, "#HttpOnly_"); if (status != LUCK_OK) return status; }
        status = luck_buffer_append_cstr(output, cookie->domain); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->host_only ? "\tFALSE\t" : "\tTRUE\t"); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->path); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->secure ? "\tTRUE\t" : "\tFALSE\t"); if (status != LUCK_OK) return status;
        written = snprintf(expiration, sizeof expiration, "%.0f", cookie->session ? 0.0 : floor(cookie->expiration_date));
        if (written < 0 || (size_t)written >= sizeof expiration) return LUCK_ERROR_INTERNAL;
        status = luck_buffer_append(output, luck_sv_n(expiration, (size_t)written)); if (status != LUCK_OK) return status;
        status = luck_buffer_append_char(output, '\t'); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->name); if (status != LUCK_OK) return status;
        status = luck_buffer_append_char(output, '\t'); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->value); if (status != LUCK_OK) return status;
        status = luck_buffer_append_char(output, '\n'); if (status != LUCK_OK) return status;
    }
    return LUCK_OK;
}

static luck_status serialize_set_cookie(const luck_cookie_collection *collection, const luck_serialize_options *options,
                                        luck_buffer *output) {
    size_t index;
    for (index = 0U; index < collection->length; index += 1U) {
        const luck_cookie *cookie = &collection->items[index];
        luck_status status;
        if (!options->include_http_only && cookie->http_only) continue;
        status = luck_buffer_append_cstr(output, "Set-Cookie: "); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->name); if (status != LUCK_OK) return status;
        status = luck_buffer_append_char(output, '='); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->value); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, "; Path="); if (status != LUCK_OK) return status;
        status = luck_buffer_append_cstr(output, cookie->path); if (status != LUCK_OK) return status;
        if (!cookie->host_only && cookie->domain[0] != '\0') {
            status = luck_buffer_append_cstr(output, "; Domain="); if (status != LUCK_OK) return status;
            status = luck_buffer_append_cstr(output, cookie->domain); if (status != LUCK_OK) return status;
        }
        if (cookie->secure) { status = luck_buffer_append_cstr(output, "; Secure"); if (status != LUCK_OK) return status; }
        if (cookie->http_only) { status = luck_buffer_append_cstr(output, "; HttpOnly"); if (status != LUCK_OK) return status; }
        if (cookie->same_site != LUCK_SAME_SITE_UNSPECIFIED) {
            const char *same_site = cookie->same_site == LUCK_SAME_SITE_NONE ? "None" : cookie->same_site == LUCK_SAME_SITE_LAX ? "Lax" : "Strict";
            status = luck_buffer_append_cstr(output, "; SameSite="); if (status != LUCK_OK) return status;
            status = luck_buffer_append_cstr(output, same_site); if (status != LUCK_OK) return status;
        }
        status = luck_buffer_append_char(output, '\n'); if (status != LUCK_OK) return status;
    }
    return LUCK_OK;
}

luck_serialize_options luck_serialize_options_default(void) {
    luck_serialize_options options = {LUCK_OUTPUT_REDACTED_JSON, false, true};
    return options;
}

const char *luck_output_format_name(luck_output_format format) {
    switch (format) {
        case LUCK_OUTPUT_JSON: return "json";
        case LUCK_OUTPUT_REDACTED_JSON: return "redacted-json";
        case LUCK_OUTPUT_NETSCAPE: return "netscape";
        case LUCK_OUTPUT_COOKIE_HEADER: return "cookie-header";
        case LUCK_OUTPUT_SET_COOKIE: return "set-cookie";
        default: return "unknown";
    }
}

luck_status luck_serialize_cookies(const luck_cookie_collection *collection, const luck_serialize_options *options,
                                   luck_buffer *output) {
    luck_serialize_options defaults;
    if (collection == NULL || output == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    defaults = luck_serialize_options_default();
    if (options == NULL) options = &defaults;
    luck_buffer_clear(output);
    switch (options->format) {
        case LUCK_OUTPUT_JSON: return serialize_json(collection, options, output, false);
        case LUCK_OUTPUT_REDACTED_JSON: return serialize_json(collection, options, output, true);
        case LUCK_OUTPUT_NETSCAPE: return serialize_netscape(collection, options, output);
        case LUCK_OUTPUT_COOKIE_HEADER: return serialize_header(collection, options, output);
        case LUCK_OUTPUT_SET_COOKIE: return serialize_set_cookie(collection, options, output);
        default: return LUCK_ERROR_UNSUPPORTED;
    }
}
