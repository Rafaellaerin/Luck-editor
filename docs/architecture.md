# Architecture

## Overview

Luck Editor is a monorepo composed of independent layers. The extension does not depend on the native libraries at runtime; they share concepts and formats but can evolve and be tested separately.

## Extension Flow

1. `popup.ts` resolves the active tab.
2. The permissions module checks for or requests access to the origin.
3. `CookieService` coordinates operations.
4. `CookieRepository` encapsulates `chrome.cookies`.
5. Importers transform text into `EditableCookie` objects.
6. The validator normalizes entries and rejects invalid ones.
7. Serializers produce explicit output.
8. Snapshots and audit logs use session storage.
9. UI components create DOM nodes without dynamic HTML.

## Rust Flow

`parse_cookies` detects the format, applies limits, creates cookies, validates them, rejects invalid entries, and removes duplicates. `LuckEngine` can canonicalize data, enforce policies, calculate statistics, index domains, filter by query, redact data, and serialize output.

Transactional storage uses optimistic revision control. A commit fails when the base revision differs from the current revision. Diffs include preconditions and conflict-resolution strategies.

## C Flow

The C API uses structures with maximum capacities and returns `luck_status`. Callers are responsible for initializing and destroying structures as specified in the headers. Strings are represented by `luck_string_view` when ownership is not required.

## C++ Flow

The C++ layer converts C structures into RAII objects and adds `CookieStore`, `DomainIndex`, `Query`, snapshots, policies, and binary file support. Concurrent operations use `std::shared_mutex`.

## Dependencies

The extension and Web Lab have no external runtime dependencies. Rust uses established crates for the CLI, serialization with Serde, error handling, URL processing, and WebAssembly. C and C++ use only the standard library and the internal C library.
