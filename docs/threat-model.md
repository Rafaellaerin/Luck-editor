# Threat Model

## Considered Adversaries

* malformed cookie files;
* web pages attempting to influence displayed data;
* contributors introducing remote resources or dynamic code execution;
* truncated or corrupted binary input;
* FFI clients providing invalid pointers;
* concurrent operations modifying a store during a transaction.

## Controls

| Threat                          | Control                                  |
| ------------------------------- | ---------------------------------------- |
| Remote scripts                  | CSP and build verification               |
| Injected HTML                   | DOM node creation and `textContent`      |
| Excessive input                 | Limits enforced before parsing           |
| Duplicates                      | Composite key with last entry winning    |
| Cookie outside the active host  | Scope verification                       |
| Insecure SameSite configuration | `Secure` required for `None`             |
| Invalid prefix                  | `__Host-` and `__Secure-` rules          |
| Corrupted binary file           | Magic value, version, size, and checksum |
| C++ race condition              | Shared mutex and versioning              |
| Stale commit                    | Optimistic revision control              |
| Secrets in exports              | Redaction by default                     |
| Secrets in snapshots            | Values removed by default                |

## Review

Changes affecting permissions, storage, parsing, serialization, FFI, or native code require an explicit security review in the pull request.
