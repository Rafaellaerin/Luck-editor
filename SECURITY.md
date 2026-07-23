# Security Policy

## Supported Versions

The 5.x release line receives security fixes. Versions prior to Luck Editor 5 have been replaced and are no longer supported.

## How to Report

Do not publish exploitable details in public issues, discussions, or pull requests.

Use the repository’s private GitHub Security Advisories feature. Include:

* affected component;
* version or commit;
* preconditions;
* impact;
* minimal reproduction steps;
* evidence that does not include real cookies, tokens, or credentials;
* suggested fix, when available.

## Sensitive Data

Never submit real cookie values, tokens, authentication headers, personal Netscape files, or snapshots containing active sessions. Replace all values with fictitious data.

## Priority Scope

High-priority reports include:

* cookie exfiltration;
* access to origins without appropriate user interaction or permission;
* code execution within extension pages;
* Content Security Policy bypasses;
* unexpected persistence of sensitive values;
* memory corruption in the C or C++ libraries;
* out-of-bounds reads or writes;
* validation flaws that allow header injection;
* vulnerabilities in the C ABI or binary parser;
* compromised dependencies.

## Out of Scope

* issues caused by loading builds modified by third parties;
* cookies deliberately exported by the user;
* internal browser pages that the extension explicitly declares unsupported;
* lack of protection against an already compromised operating system;
* social engineering without a technical flaw in the project.

## Remediation Principles

Fixes must:

* preserve the principle of least privilege;
* add a regression test;
* avoid new dependencies when a simple solution is sufficient;
* clear temporary sensitive data;
* fail explicitly and securely;
* document breaking changes.
