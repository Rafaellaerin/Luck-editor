# Contributing to Luck Editor

## Setup

Install Node.js 20 or later, stable Rust, CMake 3.20 or later, and compilers compatible with C17 and C++20.

```bash
npm install
npm run verify
cargo test --workspace --manifest-path rust/Cargo.toml
cmake -S native -B native/build -DLUCK_ENABLE_SANITIZERS=ON
cmake --build native/build --parallel
ctest --test-dir native/build --output-on-failure
```

## Project Structure

* shared rules and compute-intensive processing belong in `rust/crates/luck-core`;
* command-line integrations belong in `luck-cli`;
* FFI interfaces belong in `luck-ffi`;
* portable low-level code belongs in `native/c`;
* indexes, transactions, and native abstractions belong in `native/cpp`;
* extension APIs and UI belong in `extension/src`;
* local tools that require no build step belong in `web` or `scripts`.

## Code Requirements

* do not use real authentication data in tests;
* validate inputs before allocating, copying, or modifying cookies;
* treat compiler warnings as errors;
* keep functions small and responsibilities separate;
* add both success and failure tests;
* do not suppress critical errors;
* do not use remote dependencies in the UI;
* do not expand permissions without justification in the pull request;
* keep the interface in black and white;
* update the documentation and changelog when necessary.

## Commits and Pull Requests

Describe:

* the problem being solved;
* the chosen approach;
* the security impact;
* the tests performed;
* permission changes;
* compatibility and migration considerations.

Incomplete pull requests may be opened as drafts. Do not mix unrelated refactoring with urgent security fixes.
