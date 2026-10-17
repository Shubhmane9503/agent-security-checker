> **FICTIONAL EXAMPLE AGENT. Not a real product.** The agent below is invented for demonstration. Any keys, emails or card numbers in it are fake test values.

# Sample report: Lumen Research Assistant (fictional)

**Score: 63/100 (grade C)**

| Check | Sub-score |
|---|---|
| Prompt injection exposure | 100/100 |
| Tool permissions | 29/100 |
| Secret & data leakage | 85/100 |
| Agentic risks (multi-agent, memory) | 100/100 |
| Limits, supply chain & audit | 94/100 |

### [CRITICAL] TP-3 Untrusted input combined with an exfiltration-capable tool

Can read outside content (web_fetch) and send data out (web_fetch) without approval.

Tags: OWASP LLM01, OWASP LLM06, AML.T0051.001, AML.T0057

**Fix:** Break the chain: do not give one agent both untrusted-content access and a send/network tool, or gate the send behind human review and a destination allowlist.

### [HIGH] TP-1 High-impact tool without human confirmation

Tool "web_fetch" (network / HTTP request) has no confirmation or approval step.

Tags: OWASP LLM06, AML.T0053

**Fix:** Require explicit human approval for each call (or a pre-approved, narrowly scoped allowlist). Show the exact command, recipient, path or amount before it runs.

### [HIGH] TP-5 Overly generic tool (unrestricted capability)

Tool "web_fetch" looks general-purpose and unrestricted.

Tags: OWASP LLM06, AML.T0053

**Fix:** Replace general-purpose tools (run_any_command, http_request to any URL) with narrow, purpose-built tools that take typed parameters.

### [HIGH] DL-2 No output filtering or redaction

No output filtering, redaction or link/image allowlisting is described.

Tags: OWASP LLM05, OWASP LLM02, AML.T0057

**Fix:** Add a deterministic output filter: redact secret patterns and PII, block system-prompt text, and restrict markdown images and links to an allowlist of domains.

### [MEDIUM] TP-2 High-impact tool without scoping

Tool "web_fetch" (network / HTTP request) shows no scoping such as an allowlist, sandbox, path or amount limit.

Tags: OWASP LLM06, AML.T0053

**Fix:** Constrain the tool: allowlist commands, domains, recipients and directories; cap amounts; use a least-privilege credential; run shell and file tools in a sandbox with no secrets mounted.

### [MEDIUM] TP-2 High-impact tool without scoping

Tool "send_email" (email / messaging send) shows no scoping such as an allowlist, sandbox, path or amount limit.

Tags: OWASP LLM06, AML.T0053

**Fix:** Constrain the tool: allowlist commands, domains, recipients and directories; cap amounts; use a least-privilege credential; run shell and file tools in a sandbox with no secrets mounted.

### [LOW] RL-1 No step, time or budget limits

No maximum number of steps, tool calls, time or spend is stated.

Tags: OWASP LLM10

**Fix:** Set a maximum number of steps or tool calls, a token or spend budget, and a timeout per run.

### [LOW] AU-1 No audit logging described for high-impact tools

High-impact tools are present but no audit logging of their calls is described.

Tags: OWASP LLM06

**Fix:** Log every high-impact tool call (who, what, arguments, approval) to an append-only store you can review.

---
_Static pattern review of the configuration text. It cannot observe model behaviour; see the README for limits._
---
Share link hash (append to the demo page URL as #r=):

`eyJ2IjoxLCJzIjo2MywiYyI6eyJpbmplY3Rpb24iOjEwMCwicGVybWlzc2lvbnMiOjI5LCJsZWFrYWdlIjo4NSwiYWdlbnRpYyI6MTAwLCJnb3Zlcm5hbmNlIjo5NH0sIm4iOnsicHJvbXB0Q2hhcnMiOjM1OCwidG9vbHMiOjMsInNhbXBsZXMiOjEsImFnZW50cyI6MCwibWNwU2VydmVycyI6MH0sImYiOltbIlRQLTMiLCJjIiwiQ2FuIHJlYWQgb3V0c2lkZSBjb250ZW50ICh3ZWJfZmV0Y2gpIGFuZCBzZW5kIGRhdGEgb3V0ICh3ZWJfZmV0Y2gpIHdpdGhvdXQgYXBwcm92YWwuIiwiIl0sWyJUUC0xIiwiaCIsIlRvb2wgXCJ3ZWJfZmV0Y2hcIiAobmV0d29yayAvIEhUVFAgcmVxdWVzdCkgaGFzIG5vIGNvbmZpcm1hdGlvbiBvciBhcHByb3ZhbCBzdGVwLiIsIiJdLFsiVFAtNSIsImgiLCJUb29sIFwid2ViX2ZldGNoXCIgbG9va3MgZ2VuZXJhbC1wdXJwb3NlIGFuZCB1bnJlc3RyaWN0ZWQuIiwiIl0sWyJETC0yIiwiaCIsIk5vIG91dHB1dCBmaWx0ZXJpbmcsIHJlZGFjdGlvbiBvciBsaW5rL2ltYWdlIGFsbG93bGlzdGluZyBpcyBkZXNjcmliZWQuIiwiIl0sWyJUUC0yIiwibSIsIlRvb2wgXCJ3ZWJfZmV0Y2hcIiAobmV0d29yayAvIEhUVFAgcmVxdWVzdCkgc2hvd3Mgbm8gc2NvcGluZyBzdWNoIGFzIGFuIGFsbG93bGlzdCwgc2FuZGJveCwgcGF0aCBvciBhbW91bnQgbGltaXQuIiwiIl0sWyJUUC0yIiwibSIsIlRvb2wgXCJzZW5kX2VtYWlsXCIgKGVtYWlsIC8gbWVzc2FnaW5nIHNlbmQpIHNob3dzIG5vIHNjb3Bpbmcgc3VjaCBhcyBhbiBhbGxvd2xpc3QsIHNhbmRib3gsIHBhdGggb3IgYW1vdW50IGxpbWl0LiIsIiJdLFsiUkwtMSIsImwiLCJObyBtYXhpbXVtIG51bWJlciBvZiBzdGVwcywgdG9vbCBjYWxscywgdGltZSBvciBzcGVuZCBpcyBzdGF0ZWQuIiwiIl0sWyJBVS0xIiwibCIsIkhpZ2gtaW1wYWN0IHRvb2xzIGFyZSBwcmVzZW50IGJ1dCBubyBhdWRpdCBsb2dnaW5nIG9mIHRoZWlyIGNhbGxzIGlzIGRlc2NyaWJlZC4iLCIiXV19`
