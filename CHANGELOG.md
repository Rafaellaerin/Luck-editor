# Changelog

## 5.0.0 - 2026-07-23

### Identity

* project renamed to Luck Editor;
* interface redesigned in black and white;
* icons replaced with monochrome artwork.

### Security

* required host permissions removed;
* broad access moved to optional permissions;
* explicit and restrictive CSP;
* values masked by default;
* exports redacted by default;
* snapshots moved to session storage;
* values excluded from snapshots by default;
* validation for size, domain, path, name, value, expiration, and flags;
* confirmation prompts for deletions;
* rendering without `innerHTML`;
* tests to prevent dynamic string execution;
* CI with CodeQL and sanitizers.

### Architecture

* extension migrated to strict TypeScript;
* parsers, services, UI, storage, and validation separated;
* Rust workspace added;
* C and C++ libraries added;
* Rust CLI and native CLI added;
* C ABI and WebAssembly bindings added;
* local JavaScript Web Lab added;
* documentation and examples added.
