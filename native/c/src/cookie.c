#include "luck/cookie.h"
#include <stdlib.h>
#include <string.h>

static int cookie_compare(const void *left_pointer, const void *right_pointer) {
    const luck_cookie *left = (const luck_cookie *)left_pointer;
    const luck_cookie *right = (const luck_cookie *)right_pointer;
    int result = strcmp(left->domain, right->domain);
    if (result == 0) result = strcmp(left->path, right->path);
    if (result == 0) result = strcmp(left->name, right->name);
    if (result == 0) result = strcmp(left->store_id, right->store_id);
    return result;
}

void luck_cookie_init(luck_cookie *cookie) {
    if (cookie == NULL) return;
    memset(cookie, 0, sizeof *cookie);
    cookie->path[0] = '/';
    cookie->path[1] = '\0';
    cookie->session = true;
    cookie->host_only = true;
    cookie->same_site = LUCK_SAME_SITE_UNSPECIFIED;
}

void luck_cookie_destroy(luck_cookie *cookie) {
    if (cookie != NULL) luck_secure_zero(cookie, sizeof *cookie);
}

luck_status luck_cookie_set_name(luck_cookie *cookie, luck_string_view value) {
    return cookie == NULL ? LUCK_ERROR_INVALID_ARGUMENT : luck_copy_string(cookie->name, sizeof cookie->name, value);
}

luck_status luck_cookie_set_value(luck_cookie *cookie, luck_string_view value) {
    return cookie == NULL ? LUCK_ERROR_INVALID_ARGUMENT : luck_copy_string(cookie->value, sizeof cookie->value, value);
}

luck_status luck_cookie_set_domain(luck_cookie *cookie, luck_string_view value) {
    luck_status status;
    size_t length;
    if (cookie == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    status = luck_copy_string(cookie->domain, sizeof cookie->domain, luck_sv_trim(value));
    if (status != LUCK_OK) return status;
    luck_ascii_lower(cookie->domain);
    length = strlen(cookie->domain);
    while (length > 0U && cookie->domain[length - 1U] == '.') {
        cookie->domain[length - 1U] = '\0';
        length -= 1U;
    }
    cookie->host_only = cookie->domain[0] != '.';
    return LUCK_OK;
}

luck_status luck_cookie_set_path(luck_cookie *cookie, luck_string_view value) {
    luck_string_view trimmed;
    if (cookie == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    trimmed = luck_sv_trim(value);
    if (trimmed.length == 0U) trimmed = luck_sv("/");
    return luck_copy_string(cookie->path, sizeof cookie->path, trimmed);
}

luck_status luck_cookie_set_store_id(luck_cookie *cookie, luck_string_view value) {
    return cookie == NULL ? LUCK_ERROR_INVALID_ARGUMENT : luck_copy_string(cookie->store_id, sizeof cookie->store_id, value);
}

luck_status luck_cookie_set_partition_site(luck_cookie *cookie, luck_string_view value) {
    luck_status status;
    if (cookie == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    status = luck_copy_string(cookie->partition_site, sizeof cookie->partition_site, value);
    if (status == LUCK_OK) cookie->partitioned = value.length > 0U;
    return status;
}

size_t luck_cookie_estimated_bytes(const luck_cookie *cookie) {
    if (cookie == NULL) return 0U;
    return strlen(cookie->name) + strlen(cookie->value) + strlen(cookie->domain) + strlen(cookie->path) +
           strlen(cookie->store_id) + strlen(cookie->partition_site);
}

uint64_t luck_cookie_key_hash(const luck_cookie *cookie) {
    uint64_t hash;
    if (cookie == NULL) return 0U;
    hash = luck_fnv1a64(cookie->store_id, strlen(cookie->store_id));
    hash ^= luck_fnv1a64(cookie->partition_site, strlen(cookie->partition_site));
    hash ^= luck_fnv1a64(cookie->domain, strlen(cookie->domain));
    hash ^= luck_fnv1a64(cookie->path, strlen(cookie->path));
    hash ^= luck_fnv1a64(cookie->name, strlen(cookie->name));
    return hash;
}

bool luck_cookie_key_equal(const luck_cookie *left, const luck_cookie *right) {
    return left != NULL && right != NULL && strcmp(left->store_id, right->store_id) == 0 &&
           strcmp(left->partition_site, right->partition_site) == 0 && strcmp(left->domain, right->domain) == 0 &&
           strcmp(left->path, right->path) == 0 && strcmp(left->name, right->name) == 0;
}

bool luck_cookie_domain_matches(const luck_cookie *cookie, luck_string_view hostname) {
    luck_string_view domain;
    size_t offset;
    if (cookie == NULL || hostname.data == NULL) return false;
    domain = luck_sv(cookie->domain);
    if (domain.length > 0U && domain.data[0] == '.') { domain.data += 1; domain.length -= 1U; }
    hostname = luck_sv_trim(hostname);
    if (luck_sv_equal_ascii_case(domain, hostname)) return true;
    if (hostname.length <= domain.length) return false;
    offset = hostname.length - domain.length;
    return hostname.data[offset - 1U] == '.' && luck_sv_equal_ascii_case(luck_sv_n(hostname.data + offset, domain.length), domain);
}

bool luck_cookie_path_matches(const luck_cookie *cookie, luck_string_view request_path) {
    luck_string_view path;
    if (cookie == NULL || request_path.data == NULL) return false;
    path = luck_sv(cookie->path);
    if (luck_sv_equal(path, request_path)) return true;
    if (!luck_sv_starts_with(request_path, path)) return false;
    return path.length > 0U && (path.data[path.length - 1U] == '/' ||
           (request_path.length > path.length && request_path.data[path.length] == '/'));
}

const char *luck_same_site_name(luck_same_site value) {
    switch (value) {
        case LUCK_SAME_SITE_NONE: return "none";
        case LUCK_SAME_SITE_LAX: return "lax";
        case LUCK_SAME_SITE_STRICT: return "strict";
        case LUCK_SAME_SITE_UNSPECIFIED: return "unspecified";
        default: return "unspecified";
    }
}

luck_same_site luck_same_site_parse(luck_string_view value) {
    value = luck_sv_trim(value);
    if (luck_sv_equal_ascii_case(value, luck_sv("none")) || luck_sv_equal_ascii_case(value, luck_sv("no_restriction"))) return LUCK_SAME_SITE_NONE;
    if (luck_sv_equal_ascii_case(value, luck_sv("lax"))) return LUCK_SAME_SITE_LAX;
    if (luck_sv_equal_ascii_case(value, luck_sv("strict"))) return LUCK_SAME_SITE_STRICT;
    return LUCK_SAME_SITE_UNSPECIFIED;
}

void luck_cookie_collection_init(luck_cookie_collection *collection) {
    if (collection != NULL) { collection->items = NULL; collection->length = 0U; collection->capacity = 0U; }
}

void luck_cookie_collection_destroy(luck_cookie_collection *collection) {
    size_t index;
    if (collection == NULL) return;
    for (index = 0U; index < collection->length; index += 1U) luck_cookie_destroy(&collection->items[index]);
    free(collection->items);
    luck_cookie_collection_init(collection);
}

void luck_cookie_collection_clear(luck_cookie_collection *collection) {
    size_t index;
    if (collection == NULL) return;
    for (index = 0U; index < collection->length; index += 1U) luck_cookie_destroy(&collection->items[index]);
    collection->length = 0U;
}

luck_status luck_cookie_collection_reserve(luck_cookie_collection *collection, size_t capacity) {
    luck_cookie *replacement;
    if (collection == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    if (capacity <= collection->capacity) return LUCK_OK;
    if (capacity > SIZE_MAX / sizeof *replacement) return LUCK_ERROR_LIMIT_EXCEEDED;
    replacement = (luck_cookie *)realloc(collection->items, capacity * sizeof *replacement);
    if (replacement == NULL) return LUCK_ERROR_OUT_OF_MEMORY;
    collection->items = replacement;
    collection->capacity = capacity;
    return LUCK_OK;
}

luck_status luck_cookie_collection_push(luck_cookie_collection *collection, const luck_cookie *cookie) {
    luck_status status;
    size_t capacity;
    if (collection == NULL || cookie == NULL) return LUCK_ERROR_INVALID_ARGUMENT;
    if (collection->length == collection->capacity) {
        capacity = collection->capacity == 0U ? 16U : collection->capacity * 2U;
        if (capacity < collection->capacity) return LUCK_ERROR_LIMIT_EXCEEDED;
        status = luck_cookie_collection_reserve(collection, capacity);
        if (status != LUCK_OK) return status;
    }
    collection->items[collection->length++] = *cookie;
    return LUCK_OK;
}

size_t luck_cookie_collection_deduplicate_last_wins(luck_cookie_collection *collection) {
    size_t read_index = 0U;
    size_t removed = 0U;
    if (collection == NULL || collection->length < 2U) return 0U;
    while (read_index < collection->length) {
        size_t later;
        bool duplicate = false;
        for (later = read_index + 1U; later < collection->length; later += 1U) {
            if (luck_cookie_key_equal(&collection->items[read_index], &collection->items[later])) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            luck_cookie_destroy(&collection->items[read_index]);
            memmove(&collection->items[read_index], &collection->items[read_index + 1U],
                    (collection->length - read_index - 1U) * sizeof *collection->items);
            collection->length -= 1U;
            removed += 1U;
        } else {
            read_index += 1U;
        }
    }
    return removed;
}

void luck_cookie_collection_sort(luck_cookie_collection *collection) {
    if (collection != NULL && collection->length > 1U) qsort(collection->items, collection->length, sizeof *collection->items, cookie_compare);
}
