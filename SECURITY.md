# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security > Report a vulnerability** on this repository (private vulnerability reporting). Do not open a public issue.

Include what you found, steps to reproduce, and the impact. You can expect an acknowledgement within a few days. Please allow reasonable time for a fix before disclosing.

## Scope

In scope: the checker's code (XSS in rendered output, ReDoS, unsafe parsing, share-link tampering, anything that would send pasted configuration off the device). Out of scope: false positives or false negatives of the rules (open a normal issue), and findings that need a modified copy of the app.

## Supported versions

Only the latest release on `main`.
