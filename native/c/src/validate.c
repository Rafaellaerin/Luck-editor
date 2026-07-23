#include "luck/validate.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static bool token_byte(unsigned char byte) {
    if (isalnum(byte) != 0) return true;
    switch (byte) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+':
        case '-': case '.': case '^': case '_': case '`': case '|': case '~': return true;
        default: return false;
    }
}

static void add_issue(luck_validation_report *report, const char *code, const char *field,
                      const char *message, luck_issue_severity severity) {
    luck_validation_issue *issue;
    if (report == NULL) return;
    if (report->length >= LUCK_MAX_VALIDATION_ISSUES) { report->dropped += 1U; return; }
    issue = &report->issues[report->length++];
    (void)luck_copy_string(issue->code, sizeof issue->code, luck_sv(code));
    (void)luck_copy_string(issue->field, sizeof issue->field, luck_sv(field));
    (void)luck_copy_string(issue->message, sizeof issue->message, luck_sv(message));
    issue->severity = severity;
}

static void add_size_issue(luck_validation_report *report, const char *code, const char *field,
                           const char *label, size_t actual, size_t maximum) {
    char message[LUCK_VALIDATION_MESSAGE_CAPACITY];
    int written = snprintf(message, sizeof message, "%s is %zu bytes; maximum is %zu", label, actual, maximum);
    add_issue(report, code, field,
              written < 0 || (size_t)written >= sizeof message ? "value exceeds configured maximum" : message,
              LUCK_ISSUE_ERROR);
}

luck_validation_config luck_validation_config_default(void) {
    luck_validation_config config;
    config.maximum_name_bytes = LUCK_COOKIE_NAME_CAPACITY - 1U;
    config.maximum_value_bytes = LUCK_COOKIE_VALUE_CAPACITY - 1U;
    config.maximum_domain_bytes = LUCK_COOKIE_DOMAIN_CAPACITY - 1U;
    config.maximum_path_bytes = LUCK_COOKIE_PATH_CAPACITY - 1U;
    config.maximum_total_bytes = 4352U;
    config.require_domain = true;
    config.require_secure_for_none = true;
    config.require_secure_for_partitioned = true;
    config.warn_single_label_domain = true;
    config.reject_control_characters = true;
    return config;
}

void luck_validation_report_init(luck_validation_report *report) { if (report != NULL) memset(report, 0, sizeof *report); }

size_t luck_validation_error_count(const luck_validation_report *report) {
    size_t count = 0U;
    size_t index;
    if (report == NULL) return 0U;
    for (index = 0U; index < report->length; index += 1U) if (report->issues[index].severity == LUCK_ISSUE_ERROR) count += 1U;
    return count;
}

size_t luck_validation_warning_count(const luck_validation_report *report) {
    size_t count = 0U;
    size_t index;
    if (report == NULL) return 0U;
    for (index = 0U; index < report->length; index += 1U) if (report->issues[index].severity == LUCK_ISSUE_WARNING) count += 1U;
    return count;
}

bool luck_validation_report_is_valid(const luck_validation_report *report) { return luck_validation_error_count(report) == 0U; }

bool luck_is_valid_cookie_name(luck_string_view name) {
    size_t index;
    if (name.length == 0U || name.data == NULL) return false;
    for (index = 0U; index < name.length; index += 1U) if (!token_byte((unsigned char)name.data[index])) return false;
    return true;
}

bool luck_is_valid_domain(luck_string_view domain) {
    size_t index = 0U;
    size_t label_start;
    domain = luck_sv_trim(domain);
    if (domain.length == 0U || domain.data == NULL) return false;
    if (domain.data[0] == '.') { domain.data += 1; domain.length -= 1U; }
    if (domain.length == 0U || domain.length > 253U || domain.data[domain.length - 1U] == '.') return false;
    while (index < domain.length) {
        label_start = index;
        while (index < domain.length && domain.data[index] != '.') {
            const unsigned char byte = (unsigned char)domain.data[index];
            if (!(isalnum(byte) != 0 || byte == '-')) return false;
            index += 1U;
        }
        if (index == label_start || index - label_start > 63U || domain.data[label_start] == '-' || domain.data[index - 1U] == '-') return false;
        if (index < domain.length && ++index == domain.length) return false;
    }
    return true;
}

luck_status luck_validate_cookie(const luck_cookie *cookie, const luck_validation_config *config,
                                 luck_validation_report *report) {
    luck_validation_config defaults;
    size_t index;
    if (cookie == NULL || report == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    defaults = luck_validation_config_default();
    if (config == NULL) config = &defaults;
    luck_validation_report_init(report);

    if (!luck_is_valid_cookie_name(luck_sv(cookie->name))) add_issue(report, "name.invalid", "name", "cookie name is empty or contains a forbidden character", LUCK_ISSUE_ERROR);
    if (strlen(cookie->name) > config->maximum_name_bytes) add_size_issue(report, "name.too_long", "name", "cookie name", strlen(cookie->name), config->maximum_name_bytes);
    if (strlen(cookie->value) > config->maximum_value_bytes) add_size_issue(report, "value.too_long", "value", "cookie value", strlen(cookie->value), config->maximum_value_bytes);
    if (config->reject_control_characters) {
        for (index = 0U; cookie->value[index] != '\0'; index += 1U) {
            const unsigned char byte = (unsigned char)cookie->value[index];
            if (byte < 0x20U || byte == 0x7fU) { add_issue(report, "value.control", "value", "cookie value contains an ASCII control character", LUCK_ISSUE_ERROR); break; }
        }
    }
    if (config->require_domain && cookie->domain[0] == '\0') add_issue(report, "domain.empty", "domain", "cookie domain is required", LUCK_ISSUE_ERROR);
    else if (cookie->domain[0] != '\0' && !luck_is_valid_domain(luck_sv(cookie->domain))) add_issue(report, "domain.invalid", "domain", "cookie domain is invalid", LUCK_ISSUE_ERROR);
    if (strlen(cookie->domain) > config->maximum_domain_bytes) add_size_issue(report, "domain.too_long", "domain", "cookie domain", strlen(cookie->domain), config->maximum_domain_bytes);
    if (config->warn_single_label_domain && cookie->domain[0] != '\0' && strchr(cookie->domain, '.') == NULL && strcmp(cookie->domain, "localhost") != 0)
        add_issue(report, "domain.single_label", "domain", "single-label domain may only work in local development", LUCK_ISSUE_WARNING);
    if (cookie->path[0] != '/') add_issue(report, "path.slash", "path", "cookie path must begin with '/'", LUCK_ISSUE_ERROR);
    if (strlen(cookie->path) > config->maximum_path_bytes) add_size_issue(report, "path.too_long", "path", "cookie path", strlen(cookie->path), config->maximum_path_bytes);
    if (strchr(cookie->path, ';') != NULL) add_issue(report, "path.semicolon", "path", "cookie path cannot contain ';'", LUCK_ISSUE_ERROR);
    if (cookie->same_site == LUCK_SAME_SITE_NONE && config->require_secure_for_none && !cookie->secure)
        add_issue(report, "same_site.secure", "secure", "SameSite=None requires Secure", LUCK_ISSUE_ERROR);
    if (cookie->partitioned && config->require_secure_for_partitioned && !cookie->secure)
        add_issue(report, "partitioned.secure", "secure", "partitioned cookie requires Secure", LUCK_ISSUE_ERROR);
    if (strncmp(cookie->name, "__Secure-", 9U) == 0 && !cookie->secure)
        add_issue(report, "prefix.secure", "secure", "__Secure- cookie requires Secure", LUCK_ISSUE_ERROR);
    if (strncmp(cookie->name, "__Host-", 7U) == 0) {
        if (!cookie->secure) add_issue(report, "prefix.host.secure", "secure", "__Host- cookie requires Secure", LUCK_ISSUE_ERROR);
        if (strcmp(cookie->path, "/") != 0) add_issue(report, "prefix.host.path", "path", "__Host- cookie requires path '/'", LUCK_ISSUE_ERROR);
        if (!cookie->host_only || cookie->domain[0] == '.') add_issue(report, "prefix.host.domain", "domain", "__Host- cookie must be host-only", LUCK_ISSUE_ERROR);
    }
    if (!cookie->session && cookie->expiration_date <= 0.0) add_issue(report, "expiration.invalid", "expiration", "persistent cookie requires a positive expiration timestamp", LUCK_ISSUE_ERROR);
    if (cookie->expiration_date > 253402300799.0) add_issue(report, "expiration.range", "expiration", "expiration exceeds year 9999", LUCK_ISSUE_ERROR);
    if (luck_cookie_estimated_bytes(cookie) > config->maximum_total_bytes)
        add_size_issue(report, "cookie.too_large", "cookie", "estimated cookie size", luck_cookie_estimated_bytes(cookie), config->maximum_total_bytes);
    return luck_validation_report_is_valid(report) ? LUCK_OK : LUCK_ERROR_INVALID_COOKIE;
}
