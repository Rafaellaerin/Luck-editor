#ifndef LUCK_COOKIE_H
#define LUCK_COOKIE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "luck/status.h"
#include "luck/string.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LUCK_COOKIE_NAME_CAPACITY 257U
#define LUCK_COOKIE_VALUE_CAPACITY 4097U
#define LUCK_COOKIE_DOMAIN_CAPACITY 254U
#define LUCK_COOKIE_PATH_CAPACITY 1025U
#define LUCK_COOKIE_STORE_CAPACITY 65U
#define LUCK_COOKIE_PARTITION_CAPACITY 513U
typedef enum luck_same_site { LUCK_SAME_SITE_UNSPECIFIED = 0, LUCK_SAME_SITE_NONE = 1, LUCK_SAME_SITE_LAX = 2, LUCK_SAME_SITE_STRICT = 3 } luck_same_site;
typedef struct luck_cookie {
    char name[LUCK_COOKIE_NAME_CAPACITY]; char value[LUCK_COOKIE_VALUE_CAPACITY];
    char domain[LUCK_COOKIE_DOMAIN_CAPACITY]; char path[LUCK_COOKIE_PATH_CAPACITY];
    char store_id[LUCK_COOKIE_STORE_CAPACITY]; char partition_site[LUCK_COOKIE_PARTITION_CAPACITY];
    double expiration_date; luck_same_site same_site;
    bool secure; bool http_only; bool session; bool host_only; bool partitioned;
} luck_cookie;
typedef struct luck_cookie_collection { luck_cookie *items; size_t length; size_t capacity; } luck_cookie_collection;
void luck_cookie_init(luck_cookie *cookie);
void luck_cookie_destroy(luck_cookie *cookie);
luck_status luck_cookie_set_name(luck_cookie *cookie, luck_string_view value);
luck_status luck_cookie_set_value(luck_cookie *cookie, luck_string_view value);
luck_status luck_cookie_set_domain(luck_cookie *cookie, luck_string_view value);
luck_status luck_cookie_set_path(luck_cookie *cookie, luck_string_view value);
luck_status luck_cookie_set_store_id(luck_cookie *cookie, luck_string_view value);
luck_status luck_cookie_set_partition_site(luck_cookie *cookie, luck_string_view value);
size_t luck_cookie_estimated_bytes(const luck_cookie *cookie);
uint64_t luck_cookie_key_hash(const luck_cookie *cookie);
bool luck_cookie_key_equal(const luck_cookie *left, const luck_cookie *right);
bool luck_cookie_domain_matches(const luck_cookie *cookie, luck_string_view hostname);
bool luck_cookie_path_matches(const luck_cookie *cookie, luck_string_view request_path);
const char *luck_same_site_name(luck_same_site value);
luck_same_site luck_same_site_parse(luck_string_view value);
void luck_cookie_collection_init(luck_cookie_collection *collection);
void luck_cookie_collection_destroy(luck_cookie_collection *collection);
void luck_cookie_collection_clear(luck_cookie_collection *collection);
luck_status luck_cookie_collection_reserve(luck_cookie_collection *collection, size_t capacity);
luck_status luck_cookie_collection_push(luck_cookie_collection *collection, const luck_cookie *cookie);
size_t luck_cookie_collection_deduplicate_last_wins(luck_cookie_collection *collection);
void luck_cookie_collection_sort(luck_cookie_collection *collection);
#ifdef __cplusplus
}
#endif
#endif
