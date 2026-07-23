#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "luck/buffer.h"
#include "luck/cookie.h"
#include "luck/hash.h"
#include "luck/parser.h"
#include "luck/redact.h"
#include "luck/serialize.h"
#include "luck/string.h"
#include "luck/validate.h"

static int failures = 0;
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); failures += 1; } } while (0)

static luck_cookie sample_cookie(void) {
    luck_cookie cookie;
    luck_cookie_init(&cookie);
    CHECK(luck_cookie_set_name(&cookie, luck_sv("session")) == LUCK_OK);
    CHECK(luck_cookie_set_value(&cookie, luck_sv("secret")) == LUCK_OK);
    CHECK(luck_cookie_set_domain(&cookie, luck_sv("example.com")) == LUCK_OK);
    CHECK(luck_cookie_set_path(&cookie, luck_sv("/")) == LUCK_OK);
    cookie.secure = true;
    cookie.http_only = true;
    cookie.same_site = LUCK_SAME_SITE_LAX;
    return cookie;
}

static void test_strings(void) {
    CHECK(luck_sv_equal(luck_sv("abc"), luck_sv("abc")));
    CHECK(luck_sv_equal_ascii_case(luck_sv("ABC"), luck_sv("abc")));
    CHECK(luck_sv_find(luck_sv("hello world"), luck_sv("world")) == 6);
    CHECK(luck_constant_time_equal("secret", "secret", 6U));
    CHECK(!luck_constant_time_equal("secret", "secRet", 6U));
}

static void test_validation(void) {
    luck_cookie cookie = sample_cookie();
    luck_validation_report report;
    CHECK(luck_validate_cookie(&cookie, NULL, &report) == LUCK_OK);
    (void)luck_cookie_set_name(&cookie, luck_sv("bad name"));
    CHECK(luck_validate_cookie(&cookie, NULL, &report) == LUCK_ERROR_INVALID_COOKIE);
    CHECK(luck_validation_error_count(&report) > 0U);
    luck_cookie_destroy(&cookie);
}

static void test_parsers(void) {
    luck_cookie_collection cookies;
    luck_parse_options options = luck_parse_options_default();
    luck_parse_report report;
    luck_cookie_collection_init(&cookies);
    options.fallback_domain = "example.com";
    CHECK(luck_parse_cookies(luck_sv("Cookie: a=1; b=2"), &options, &cookies, &report) == LUCK_OK);
    CHECK(cookies.length == 2U);
    CHECK(luck_parse_cookies(luck_sv("Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"), &options, &cookies, &report) == LUCK_OK);
    CHECK(cookies.length == 1U);
    CHECK(cookies.items[0].secure && cookies.items[0].http_only);
    luck_cookie_collection_destroy(&cookies);
}

static void test_redaction(void) {
    char output[64];
    luck_redaction_options options = luck_redaction_options_default();
    CHECK(luck_redact_value(luck_sv("abcdefghij"), &options, output, sizeof output) == LUCK_OK);
    CHECK(strcmp(output, "abc****hij") == 0);
    options.mode = LUCK_REDACT_HASH;
    CHECK(luck_redact_value(luck_sv("secret"), &options, output, sizeof output) == LUCK_OK);
    CHECK(strncmp(output, "redacted-", 9U) == 0);
}

static void test_hash(void) {
    luck_sha256 context;
    unsigned char digest[LUCK_SHA256_DIGEST_SIZE];
    char hex[LUCK_SHA256_HEX_SIZE];
    luck_sha256_init(&context);
    luck_sha256_update(&context, "abc", 3U);
    luck_sha256_final(&context, digest);
    luck_sha256_hex(digest, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

static void test_serialization(void) {
    luck_cookie_collection cookies;
    luck_cookie cookie = sample_cookie();
    luck_buffer output;
    luck_serialize_options options = luck_serialize_options_default();
    luck_cookie_collection_init(&cookies);
    luck_buffer_init(&output);
    CHECK(luck_cookie_collection_push(&cookies, &cookie) == LUCK_OK);
    options.include_http_only = true;
    CHECK(luck_serialize_cookies(&cookies, &options, &output) == LUCK_OK);
    CHECK(strstr(output.data, "[REDACTED]") != NULL);
    CHECK(strstr(output.data, "secret") == NULL);
    options.format = LUCK_OUTPUT_NETSCAPE;
    CHECK(luck_serialize_cookies(&cookies, &options, &output) == LUCK_OK);
    CHECK(strstr(output.data, "#HttpOnly_example.com") != NULL);
    luck_buffer_destroy(&output);
    luck_cookie_collection_destroy(&cookies);
    luck_cookie_destroy(&cookie);
}

int main(void) {
    test_strings(); test_validation(); test_parsers(); test_redaction(); test_hash(); test_serialization();
    if (failures != 0) { fprintf(stderr, "%d native C tests failed\n", failures); return EXIT_FAILURE; }
    puts("all native C tests passed");
    return EXIT_SUCCESS;
}
