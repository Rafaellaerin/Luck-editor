# Luck Editor

Luck Editor is an open-source project for inspecting, validating, editing, importing, and exporting cookies. The repository combines a Chromium Manifest V3 extension, a primary Rust core, native C and C++ libraries, a JavaScript lab interface, and a strictly typed TypeScript codebase.

The project was rebuilt to replace the previous small, monolithic structure with separate modules, automated tests, defensive validation, permissions requested only when needed, technical documentation, and reusable tools.

## Goals

Luck Editor was designed with the following goals:

- edit cookies for the current page with validation before every change;
- reduce permanent permissions and request access per origin;
- prevent dynamic code execution and unsafe HTML insertion;
- provide strict imports in multiple formats;
- export in a redacted format by default;
- keep snapshots only in the browser session by default;
- provide reusable libraries in Rust, C, and C++;
- provide a CLI for validation, conversion, querying, and auditing;
- maintain an exclusively black-and-white visual interface;
- support public review and contributions through CI, tests, and static analysis.

## Components

### Chromium Extension

The extension is located in `extension/` and uses TypeScript with strict settings. It provides:

- access to cookies from the active page;
- search by name, value, domain, and path;
- values masked by default;
- creation and editing with validation for name, value, domain, path, SameSite, Secure, HttpOnly, and expiration;
- individual and bulk deletion with configurable confirmation;
- import from JSON, Netscape, `Cookie` headers, `Set-Cookie` lines, and `name=value` lines;
- export to redacted JSON, JSON, Netscape, `Cookie` headers, `Set-Cookie` lines, and curl commands;
- temporary snapshots in `chrome.storage.session`;
- local operation auditing without storing cookie values;
- optional access to all sites, never required in the manifest;
- a restrictive Content Security Policy;
- no remote libraries, analytics, or telemetry.

### Rust Core

The workspace in `rust/` contains four crates:

- `luck-core`: data model, parsing, validation, canonicalization, policies, queries, serialization, redaction, diffs, domain indexing, statistics, transactional storage, auditing, and a binary archive;
- `luck-cli`: commands for converting, validating, querying, and auditing cookie files;
- `luck-ffi`: a C ABI for integrating the Rust core with other languages;
- `luck-wasm`: WebAssembly bindings for local use in web applications.

Rust is the repository's primary language and contains the most extensive domain rules.

### C Library

The library in `native/c/` implements a portable, low-level foundation:

- buffers with explicit limits;
- strings with known lengths;
- secure memory clearing;
- constant-time comparison;
- cookie structures with maximum capacities;
- syntax and attribute validation;
- parsers for common formats;
- controlled serialization;
- value redaction;
- FNV and SHA-256;
- deterministic collection, sorting, and deduplication;
- tests compiled with warnings treated as errors.

### C++ Library

The library in `native/cpp/` adds higher-level abstractions:

- concurrent, versioned storage;
- optimistic transactions;
- a domain index;
- a query language;
- reversible diffs;
- snapshots with fingerprints;
- statistics;
- a policy engine;
- a binary archive with checksums and limits;
- a native demonstration CLI.

### Web Lab

`web/` contains a static application written in JavaScript, HTML, and CSS. It works without a remote server and allows files to be analyzed locally. The Web Lab does not access browser cookies and does not replace the extension; it is intended for parsing, validation, canonicalization, and conversion of manually supplied data.

## Security Model

Cookies may contain session credentials. Luck Editor treats their values as sensitive data.

### Applied Principles

1. Least privilege

   The manifest does not declare permanent `host_permissions`. Access to HTTP and HTTPS origins is listed under `optional_host_permissions` and requested only when necessary.

2. Local processing

   The extension and Web Lab do not send cookies to external services. There are no remote scripts, analytics, tracking pixels, telemetry, or third-party APIs.

3. Redacted output by default

   The initial export format is redacted JSON. Non-redacted exports display a sensitive-data warning.

4. Temporary storage

   Snapshots use `chrome.storage.session`. Values are removed from snapshots by default. The user must explicitly enable temporary value storage.

5. Safe rendering

   User-controlled data is inserted using `textContent` and explicit node creation. The code does not use `innerHTML`, `eval`, or `new Function`.

6. Resource limits

   Inputs, files, names, values, domains, paths, snapshots, and cookie counts have defined limits to reduce memory abuse and malformed input.

7. Validation before mutation

   No cookie is created or modified without passing through the validator. Special rules for `__Host-`, `__Secure-`, and `SameSite=None` are checked.

8. Explicit failures

   Errors are not silently ignored in core operations. Reports identify imported, skipped, and rejected items.

Read `SECURITY.md` and `docs/security-model.md` for details.

## Extension Permissions

The manifest uses only:

- `activeTab`: temporary context for the active tab;
- `cookies`: reading and modifying cookies;
- `storage`: local settings, temporary snapshots, and session auditing.

The `http://*/*` and `https://*/*` origins are optional. Normal mode works with the current site. Viewing all domains requires an explicit user action.

## Installing the Extension for Development

Requirements:

- Node.js 20 or later;
- npm;
- Chrome, Chromium, Edge, or another Manifest V3-compatible browser.

Run:

```bash
npm install
npm run verify
```

The build will be created in:

```text
dist/extension/
```

In the browser:

1. open the extensions page;
2. enable developer mode;
3. choose the option to load an unpacked extension;
4. select the `dist/extension` directory.

To create the ZIP package:

```bash
npm run package
```

The file will be created at:

```text
dist/luck-editor-extension.zip
```

## Using the Extension

### Cookies for the Current Page

Open an HTTP or HTTPS page and click the Luck Editor icon. The list shows cookies available for the current origin and domain. Values are masked by default.

### Add or Edit

Use `Add` or `Edit`. The form validates:

- names using the token format allowed for cookies;
- values without control characters;
- valid domains limited to the active host;
- paths beginning with `/`;
- positive expiration values;
- `SameSite=None` accompanied by `Secure`;
- requirements for the `__Host-` and `__Secure-` prefixes.

### Import

Paste content or open a file. The parser detects the format, validates each entry, removes duplicates, and displays errors and warnings before import.

Available options:

- force `Secure`;
- force `HttpOnly`;
- overwrite existing cookies;
- preserve session cookies.

### Export

The user can export all listed cookies or only the selected ones. Redacted JSON is the initial option. Including HttpOnly cookies must be enabled in the settings.

### Snapshots

Snapshots are useful for comparing or restoring sets during the current session. They are not permanent backups. Values are empty by default.

## Supported Formats

### Input

- JSON as an array of cookies;
- JSON with a `cookies` property;
- JSON as a name-to-value map;
- Netscape HTTP Cookie File;
- `Cookie` header;
- `Set-Cookie` lines;
- one `name=value` entry per line.

### Output

- JSON;
- redacted JSON;
- Netscape;
- `Cookie` header;
- `Set-Cookie` lines;
- curl command.

## Rust CLI

The CLI is named `luck`.

Validate a file:

```bash
cargo run --manifest-path rust/Cargo.toml -p luck-cli -- \
  validate --input examples/cookies/sample.json --domain example.com
```

Convert to redacted JSON:

```bash
cargo run --manifest-path rust/Cargo.toml -p luck-cli -- \
  convert --input examples/cookies/sample.json \
  --domain example.com \
  --output-format redacted-json
```

Query only secure cookies for a domain:

```bash
cargo run --manifest-path rust/Cargo.toml -p luck-cli -- \
  query --input examples/cookies/sample.json \
  --domain example.com \
  "domain:example.com and secure:true"
```

Audit with an allowlist:

```bash
cargo run --manifest-path rust/Cargo.toml -p luck-cli -- \
  audit --input examples/cookies/sample.json \
  --allow-domain example.com \
  --require-secure
```

## Rust Library

Minimal example:

```rust
use luck_core::{parse_cookies, CookiePolicy, ParseOptions};

fn main() -> luck_core::Result<()> {
    let options = ParseOptions {
        fallback_domain: "example.com".into(),
        ..ParseOptions::default()
    };
    let report = parse_cookies("session=test", &options)?;
    let policy = CookiePolicy::default();

    for cookie in &report.cookies {
        println!("{}: {:?}", cookie.name, policy.evaluate(cookie));
    }
    Ok(())
}
```

Main `luck-core` modules:

- `parse`: multi-format detection and parsing;
- `validation`: syntax and security rules;
- `canonical`: deterministic normalization;
- `policy`: Allow, AllowWithWarnings, and Deny decisions;
- `query`: Boolean expressions for searching;
- `serialize`: output conversion;
- `redact`: masking and deterministic pseudonyms;
- `diff`: comparison and application of changes;
- `domain_index`: domain and flag indexing;
- `statistics`: security, size, and lifetime metrics;
- `store`: transactional storage with revisions and rollback;
- `binary`: a versioned binary format with a checksum;
- `audit`: a bounded in-memory log;
- `engine`: an integrated pipeline.

## Native Libraries

Requirements:

- CMake 3.20 or later;
- a C17 compiler;
- a C++20 compiler.

Standard build:

```bash
cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/build --parallel
ctest --test-dir native/build --output-on-failure
```

Build with sanitizers:

```bash
cmake -S native -B native/build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DLUCK_ENABLE_SANITIZERS=ON
cmake --build native/build --parallel
ctest --test-dir native/build --output-on-failure
```

GCC and Clang builds treat warnings as errors. When sanitizers are enabled, the tests use AddressSanitizer and UndefinedBehaviorSanitizer.

## Web Lab

Start a local server with security headers:

```bash
npm run serve:web
```

Open the address displayed by the command. The server listens only on `127.0.0.1`, disables caching, and applies a Content Security Policy with no external connections.

## Repository Structure

```text
Luck-Editor/
├── extension/
│   ├── assets/
│   ├── manifest.json
│   └── src/
│       ├── background/
│       ├── cookies/
│       ├── core/
│       ├── export/
│       ├── import/
│       ├── popup/
│       ├── snapshots/
│       ├── styles/
│       ├── types/
│       └── ui/
├── rust/
│   └── crates/
│       ├── luck-cli/
│       ├── luck-core/
│       ├── luck-ffi/
│       └── luck-wasm/
├── native/
│   ├── c/
│   ├── cpp/
│   └── tools/
├── web/
│   ├── js/
│   ├── index.html
│   └── styles.css
├── tests/
├── scripts/
├── examples/
├── docs/
└── .github/
```

## Why the Project Uses Multiple Languages

The languages were not added merely to increase statistics. Each one has a defined responsibility:

- Rust contains domain rules, parsing, policies, transactions, formats, and integrations;
- C provides a small, predictable, portable ABI for low-level operations;
- C++ provides concurrent structures, indexes, transactions, and native tools;
- TypeScript implements the extension with strict types for browser APIs and the interface;
- JavaScript implements build tools, validation, and the Web Lab without a compilation step;
- HTML defines accessible interfaces without remote dependencies;
- CSS maintains an exclusively black-and-white visual system.

The language count can be viewed with:

```bash
npm run report:languages
```

Generated directories, dependencies, and build artifacts are ignored by the report.

## Testing and Verification

Extension and Web Lab verification:

```bash
npm run verify
```

Rust tests:

```bash
cargo fmt --all --manifest-path rust/Cargo.toml
cargo check --workspace --all-targets --manifest-path rust/Cargo.toml
cargo clippy --workspace --all-targets --manifest-path rust/Cargo.toml
cargo test --workspace --manifest-path rust/Cargo.toml
```

Native tests:

```bash
cmake -S native -B native/build -DLUCK_ENABLE_SANITIZERS=ON
cmake --build native/build --parallel
ctest --test-dir native/build --output-on-failure
```

Complete verification with Make:

```bash
make all
```

## CI and Security Analysis

The workflows in `.github/workflows/` run:

- TypeScript type checking;
- Node tests;
- extension build and validation;
- extension packaging;
- Cargo check for all targets;
- Clippy for the entire workspace;
- tests for the entire Rust workspace;
- C and C++ builds;
- native tests with sanitizers;
- CodeQL for JavaScript, TypeScript, C, and C++.

Workflow permissions are minimal and explicitly declared.

## Migration from the Previous Project

The old version must not be mixed with the new files. Remove the previous extension from the browser and load only `dist/extension`.

Main changes:

- name changed to Luck Editor;
- Manifest V3 revised;
- host permissions moved to optional access;
- monolithic JavaScript replaced with modular TypeScript;
- validation centralized;
- import and export rewritten;
- persistent session storage removed;
- temporary, redacted snapshots;
- interface rebuilt in black and white;
- Rust, C, and C++ libraries added;
- tests, CI, and documentation added.

Read `docs/migration.md` for more details.

## Limitations

- The extension is designed for Chromium browsers with Manifest V3.
- Internal browser pages, local files, and URLs that do not use HTTP or HTTPS are not supported.
- Some cookie rules depend on the browser and may cause rejection even after local validation.
- Domain validation does not replace a complete public suffix list.
- The Set-Cookie parser accepts the most common attributes; unknown attributes generate a warning.
- The Web Lab does not access the browser's cookie storage.
- Snapshots are not permanent backups.

## Contributing

Read `CONTRIBUTING.md`. Pull requests must include tests for new rules, pass CI, and preserve the least-privilege model.

Do not add:

- telemetry;
- remote scripts;
- required permissions without justification;
- permanent storage of cookie values by default;
- `eval`, `new Function`, or `innerHTML` with external data;
- code without a technical purpose solely to inflate the line count.

## Vulnerability Disclosure

Do not open a public issue for a vulnerability that is still exploitable. Follow `SECURITY.md`.

## License

Luck Editor is distributed under the MIT License. See `LICENSE`.
#   L u c k - e d i t o r  
 