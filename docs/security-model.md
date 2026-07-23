# Security Model

## Protected Assets

* cookie values;
* session tokens and identifiers;
* cookie domains and scope;
* integrity of user-made changes;
* native process memory;
* browser-authorized origins.

## Trust Boundaries

* pasted text and imported files are untrusted;
* cookies returned by the browser API may contain unexpected data;
* snapshot names and queries are untrusted;
* binary files are untrusted;
* parameters received through the C ABI are untrusted;
* data displayed in the UI is never treated as HTML.

## Primary Threats

### Exfiltration

Mitigations: no remote connections, no telemetry, a CSP with no external resources, redacted exports by default, and snapshots without values by default.

### Privilege Escalation

Mitigations: optional host permissions, explicit action required for access to all domains, and restriction to HTTP and HTTPS.

### Injection

Mitigations: prohibition of `eval`, `new Function`, and `innerHTML`; rejection of control characters and line breaks; serializer sanitization.

### Denial of Service

Mitigations: limits on bytes, item counts, fields, metadata, snapshots, and history; binary parsers perform bounds checks before advancing.

### Memory Corruption

Mitigations: C with explicit capacities, bounded copy functions, initialization, and cleanup; C++ with RAII; testing with ASan and UBSan; memory-safe Rust in the core.

### Domain Confusion

Mitigations: normalization, scope verification, host-only rules, cookie prefixes, and allowlist/denylist policies.

## Persisted Data

`chrome.storage.local` stores settings only. `chrome.storage.session` stores temporary snapshots and audit data. Cookie values are not persisted by default.

## Non-Goals

Luck Editor does not protect data against local malware, malicious extensions with equivalent privileges, a compromised browser, or users who export and share their own secrets.
