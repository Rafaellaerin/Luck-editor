# Native Core

## C API

Public headers are located in `native/c/include/luck`.

Main groups:

* `buffer.h`: bounded growth and cleanup;
* `string.h`: views, copying, and comparison;
* `cookie.h`: data model and collection;
* `validate.h`: validation reports;
* `parser.h`: text formats;
* `serialize.h`: output formats;
* `redact.h`: value masking;
* `hash.h`: fingerprints;
* `status.h`: return codes.

All functions that may fail return a documented status or result. Callers must not access fields beyond the specified lengths.

## C++ API

Public headers are located in `native/cpp/include/luck`.

* `model.hpp`: RAII model and C conversion;
* `store.hpp`: concurrent store and transactions;
* `domain_index.hpp`: hierarchical index;
* `query.hpp`: query parser and executor;
* `diff.hpp`: reversible changes;
* `snapshot.hpp`: bounded snapshots;
* `statistics.hpp`: metrics;
* `policy.hpp`: security evaluation;
* `archive.hpp`: versioned binary archive.

## Sanitizers

Use `LUCK_ENABLE_SANITIZERS=ON` for Clang or GCC builds. The project does not enable sanitizers automatically in Release builds to avoid affecting consumers’ ABI and performance.
