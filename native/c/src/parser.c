#include "luck/parser.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void report_message(luck_parse_report *report, size_t line, const char *message) {
    if (report != NULL && report->first_error_line == 0U) {
        report->first_error_line = line;
        (void)luck_copy_string(report->message, sizeof report->message, luck_sv(message));
    }
}

static luck_status set_pair(luck_cookie *cookie, luck_string_view pair, const char *fallback_domain) {
    ptrdiff_t separator = luck_sv_find_byte(pair, '=');
    luck_status status;
    if (separator <= 0) return LUCK_ERROR_PARSE;
    status = luck_cookie_set_name(cookie, luck_sv_trim(luck_sv_n(pair.data, (size_t)separator)));
    if (status != LUCK_OK) return status;
    status = luck_cookie_set_value(cookie, luck_sv_trim(luck_sv_n(pair.data + separator + 1, pair.length - (size_t)separator - 1U)));
    if (status != LUCK_OK) return status;
    return fallback_domain == NULL || fallback_domain[0] == '\0' ? LUCK_OK : luck_cookie_set_domain(cookie, luck_sv(fallback_domain));
}

static luck_status accept_cookie(luck_cookie_collection *output, luck_cookie *cookie,
                                 const luck_parse_options *options, luck_parse_report *report, size_t line) {
    luck_validation_report validation;
    luck_status status = luck_validate_cookie(cookie, &options->validation, &validation);
    report->warnings += luck_validation_warning_count(&validation);
    if (status != LUCK_OK && options->reject_invalid) {
        report->rejected += 1U;
        if (validation.length > 0U) report_message(report, line, validation.issues[0].message);
        return LUCK_OK;
    }
    status = luck_cookie_collection_push(output, cookie);
    if (status == LUCK_OK) report->parsed += 1U;
    return status;
}

static luck_status parse_pair(luck_string_view pair, const luck_parse_options *options,
                              luck_cookie_collection *output, luck_parse_report *report, size_t line) {
    luck_cookie cookie;
    luck_status status;
    luck_cookie_init(&cookie);
    status = set_pair(&cookie, pair, options->fallback_domain);
    if (status == LUCK_ERROR_PARSE) {
        report->warnings += 1U;
        report_message(report, line, "line has no valid name=value pair");
        status = LUCK_OK;
    } else if (status == LUCK_OK) {
        status = accept_cookie(output, &cookie, options, report, line);
    }
    luck_cookie_destroy(&cookie);
    return status;
}

static luck_status parse_lines(luck_string_view input, const luck_parse_options *options,
                               luck_cookie_collection *output, luck_parse_report *report) {
    size_t start = 0U;
    size_t line = 1U;
    while (start <= input.length) {
        size_t end = start;
        luck_string_view current;
        while (end < input.length && input.data[end] != '\n') end += 1U;
        current = luck_sv_trim(luck_sv_n(input.data + start, end - start));
        if (current.length > 0U && current.data[0] != '#') {
            luck_status status = parse_pair(current, options, output, report, line);
            if (status != LUCK_OK) return status;
        }
        if (end == input.length) break;
        start = end + 1U;
        line += 1U;
    }
    return LUCK_OK;
}

static luck_status parse_header(luck_string_view input, const luck_parse_options *options,
                                luck_cookie_collection *output, luck_parse_report *report) {
    size_t start = 0U;
    input = luck_sv_trim(input);
    if (luck_sv_starts_with_ascii_case(input, luck_sv("cookie:"))) { input.data += 7U; input.length -= 7U; }
    while (start <= input.length) {
        size_t end = start;
        luck_string_view pair;
        while (end < input.length && input.data[end] != ';' && input.data[end] != '\n') end += 1U;
        pair = luck_sv_trim(luck_sv_n(input.data + start, end - start));
        if (pair.length > 0U) {
            luck_status status = parse_pair(pair, options, output, report, 1U);
            if (status != LUCK_OK) return status;
        }
        if (end == input.length) break;
        start = end + 1U;
    }
    return LUCK_OK;
}

static luck_status parse_set_cookie_line(luck_string_view line_view, const luck_parse_options *options,
                                         luck_cookie_collection *output, luck_parse_report *report, size_t line_number) {
    size_t start = 0U;
    size_t segment_index = 0U;
    luck_cookie cookie;
    luck_status status = LUCK_OK;
    line_view = luck_sv_trim(line_view);
    if (luck_sv_starts_with_ascii_case(line_view, luck_sv("set-cookie:"))) { line_view.data += 11U; line_view.length -= 11U; }
    line_view = luck_sv_trim(line_view);
    luck_cookie_init(&cookie);
    while (start <= line_view.length) {
        size_t end = start;
        luck_string_view segment;
        ptrdiff_t separator;
        while (end < line_view.length && line_view.data[end] != ';') end += 1U;
        segment = luck_sv_trim(luck_sv_n(line_view.data + start, end - start));
        separator = luck_sv_find_byte(segment, '=');
        if (segment_index == 0U) {
            status = set_pair(&cookie, segment, options->fallback_domain);
            if (status != LUCK_OK) {
                report->rejected += 1U;
                report_message(report, line_number, "Set-Cookie line has no valid pair");
                status = LUCK_OK;
                goto cleanup;
            }
        } else if (segment.length > 0U) {
            luck_string_view key = separator < 0 ? segment : luck_sv_n(segment.data, (size_t)separator);
            luck_string_view value = separator < 0 ? luck_sv_n(NULL, 0U) : luck_sv_n(segment.data + separator + 1, segment.length - (size_t)separator - 1U);
            key = luck_sv_trim(key);
            value = luck_sv_trim(value);
            if (luck_sv_equal_ascii_case(key, luck_sv("domain"))) status = luck_cookie_set_domain(&cookie, value);
            else if (luck_sv_equal_ascii_case(key, luck_sv("path"))) status = luck_cookie_set_path(&cookie, value);
            else if (luck_sv_equal_ascii_case(key, luck_sv("secure"))) cookie.secure = true;
            else if (luck_sv_equal_ascii_case(key, luck_sv("httponly"))) cookie.http_only = true;
            else if (luck_sv_equal_ascii_case(key, luck_sv("samesite"))) cookie.same_site = luck_same_site_parse(value);
            else if (luck_sv_equal_ascii_case(key, luck_sv("partitioned"))) { cookie.partitioned = true; cookie.secure = true; }
            else if (luck_sv_equal_ascii_case(key, luck_sv("max-age"))) {
                char temporary[32];
                char *tail = NULL;
                long long seconds;
                status = luck_copy_string(temporary, sizeof temporary, value);
                if (status != LUCK_OK) goto cleanup;
                errno = 0;
                seconds = strtoll(temporary, &tail, 10);
                if (errno == 0 && tail != temporary && *tail == '\0') { cookie.expiration_date = (double)seconds; cookie.session = false; }
                else report->warnings += 1U;
            } else if (!luck_sv_equal_ascii_case(key, luck_sv("expires")) && !luck_sv_equal_ascii_case(key, luck_sv("priority"))) {
                report->warnings += 1U;
            }
            if (status != LUCK_OK) goto cleanup;
        }
        segment_index += 1U;
        if (end == line_view.length) break;
        start = end + 1U;
    }
    status = accept_cookie(output, &cookie, options, report, line_number);
cleanup:
    luck_cookie_destroy(&cookie);
    return status;
}

static luck_status parse_set_cookie(luck_string_view input, const luck_parse_options *options,
                                    luck_cookie_collection *output, luck_parse_report *report) {
    size_t start = 0U;
    size_t line = 1U;
    while (start <= input.length) {
        size_t end = start;
        luck_string_view current;
        while (end < input.length && input.data[end] != '\n') end += 1U;
        current = luck_sv_trim(luck_sv_n(input.data + start, end - start));
        if (current.length > 0U) {
            luck_status status = parse_set_cookie_line(current, options, output, report, line);
            if (status != LUCK_OK) return status;
        }
        if (end == input.length) break;
        start = end + 1U;
        line += 1U;
    }
    return LUCK_OK;
}

static bool parse_boolean(luck_string_view value) {
    value = luck_sv_trim(value);
    return luck_sv_equal_ascii_case(value, luck_sv("true")) || luck_sv_equal(value, luck_sv("1"));
}

static luck_status parse_netscape(luck_string_view input, const luck_parse_options *options,
                                  luck_cookie_collection *output, luck_parse_report *report) {
    size_t start = 0U;
    size_t line_number = 1U;
    (void)options;
    while (start <= input.length) {
        size_t end = start;
        luck_string_view line;
        bool http_only = false;
        while (end < input.length && input.data[end] != '\n') end += 1U;
        line = luck_sv_trim(luck_sv_n(input.data + start, end - start));
        if (luck_sv_starts_with(line, luck_sv("#HttpOnly_"))) { http_only = true; line.data += 10U; line.length -= 10U; }
        else if (line.length == 0U || line.data[0] == '#') goto next_line;
        {
            luck_string_view fields[7];
            size_t field_count = 0U;
            size_t field_start = 0U;
            luck_cookie cookie;
            luck_status status = LUCK_OK;
            while (field_count < 7U && field_start <= line.length) {
                size_t field_end = field_start;
                while (field_end < line.length && line.data[field_end] != '\t') field_end += 1U;
                fields[field_count++] = luck_sv_n(line.data + field_start, field_end - field_start);
                if (field_end == line.length) break;
                field_start = field_end + 1U;
            }
            if (field_count < 7U) {
                report->warnings += 1U;
                report_message(report, line_number, "Netscape line requires seven tab-separated fields");
                goto next_line;
            }
            luck_cookie_init(&cookie);
            status = luck_cookie_set_domain(&cookie, fields[0]);
            if (status == LUCK_OK) status = luck_cookie_set_path(&cookie, fields[2]);
            if (status == LUCK_OK) status = luck_cookie_set_name(&cookie, fields[5]);
            if (status == LUCK_OK) status = luck_cookie_set_value(&cookie, fields[6]);
            cookie.host_only = !parse_boolean(fields[1]);
            cookie.secure = parse_boolean(fields[3]);
            cookie.http_only = http_only;
            {
                char expiration[32];
                char *tail = NULL;
                if (luck_copy_string(expiration, sizeof expiration, fields[4]) == LUCK_OK) {
                    cookie.expiration_date = strtod(expiration, &tail);
                    cookie.session = tail == expiration || cookie.expiration_date <= 0.0;
                }
            }
            if (status == LUCK_OK) status = accept_cookie(output, &cookie, options, report, line_number);
            luck_cookie_destroy(&cookie);
            if (status != LUCK_OK) return status;
        }
next_line:
        if (end == input.length) break;
        start = end + 1U;
        line_number += 1U;
    }
    return LUCK_OK;
}

luck_parse_options luck_parse_options_default(void) {
    luck_parse_options options;
    options.format = LUCK_INPUT_AUTO;
    options.fallback_domain = "";
    options.maximum_input_bytes = 2U * 1024U * 1024U;
    options.maximum_cookies = 5000U;
    options.reject_invalid = true;
    options.deduplicate = true;
    options.validation = luck_validation_config_default();
    return options;
}

luck_input_format luck_detect_input_format(luck_string_view input) {
    luck_string_view trimmed = luck_sv_trim(input);
    if (luck_sv_find(input, luck_sv("\t")) >= 0) return LUCK_INPUT_NETSCAPE;
    if (luck_sv_starts_with_ascii_case(trimmed, luck_sv("set-cookie:")) || luck_sv_find(input, luck_sv("; Secure")) >= 0 || luck_sv_find(input, luck_sv("; HttpOnly")) >= 0) return LUCK_INPUT_SET_COOKIE;
    if (luck_sv_starts_with_ascii_case(trimmed, luck_sv("cookie:")) || luck_sv_find(input, luck_sv(";")) >= 0) return LUCK_INPUT_COOKIE_HEADER;
    return LUCK_INPUT_LINES;
}

const char *luck_input_format_name(luck_input_format format) {
    switch (format) {
        case LUCK_INPUT_AUTO: return "auto";
        case LUCK_INPUT_COOKIE_HEADER: return "cookie-header";
        case LUCK_INPUT_SET_COOKIE: return "set-cookie";
        case LUCK_INPUT_LINES: return "lines";
        case LUCK_INPUT_NETSCAPE: return "netscape";
        default: return "unknown";
    }
}

luck_status luck_parse_cookies(luck_string_view input, const luck_parse_options *options,
                               luck_cookie_collection *output, luck_parse_report *report) {
    luck_parse_options defaults;
    luck_input_format format;
    luck_status status;
    if (output == NULL || report == NULL || input.data == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    defaults = luck_parse_options_default();
    if (options == NULL) options = &defaults;
    memset(report, 0, sizeof *report);
    if (input.length == 0U) return LUCK_ERROR_PARSE;
    if (input.length > options->maximum_input_bytes) return LUCK_ERROR_LIMIT_EXCEEDED;
    luck_cookie_collection_clear(output);
    format = options->format == LUCK_INPUT_AUTO ? luck_detect_input_format(input) : options->format;
    report->format = format;
    switch (format) {
        case LUCK_INPUT_COOKIE_HEADER: status = parse_header(input, options, output, report); break;
        case LUCK_INPUT_SET_COOKIE: status = parse_set_cookie(input, options, output, report); break;
        case LUCK_INPUT_LINES: status = parse_lines(input, options, output, report); break;
        case LUCK_INPUT_NETSCAPE: status = parse_netscape(input, options, output, report); break;
        case LUCK_INPUT_AUTO: status = LUCK_ERROR_INTERNAL; break;
        default: status = LUCK_ERROR_UNSUPPORTED; break;
    }
    if (status != LUCK_OK) return status;
    if (output->length > options->maximum_cookies) { luck_cookie_collection_clear(output); return LUCK_ERROR_LIMIT_EXCEEDED; }
    if (options->deduplicate) report->duplicates_removed = luck_cookie_collection_deduplicate_last_wins(output);
    luck_cookie_collection_sort(output);
    return LUCK_OK;
}
