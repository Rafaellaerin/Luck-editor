# Testing Strategy

## JavaScript and TypeScript

* manifest and permissions;
* CSP;
* absence of dynamic code execution;
* absence of `innerHTML` in TypeScript modules;
* format detection;
* deduplication;
* canonicalization;
* control character validation;
* redaction.

## Rust

* parsing of each format;
* rejection of invalid cookies;
* prefix and SameSite rules;
* policies;
* queries with grouping and negation;
* serializers;
* redaction;
* canonicalization;
* diff generation and inversion;
* binary archive and checksum;
* domain index;
* statistics;
* store and rollback.

## C

* buffers and strings;
* validation;
* parsers;
* serialization;
* redaction;
* hashes;
* collection handling and deduplication.

## C++

* store and transactional conflicts;
* domain index;
* queries;
* diffs;
* snapshots;
* policies;
* binary archive;
* statistics.
