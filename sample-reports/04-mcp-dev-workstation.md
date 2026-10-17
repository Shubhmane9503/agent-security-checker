> **FICTIONAL EXAMPLE AGENT. Not a real product. Keys are fake documented examples.** The agent below is invented for demonstration. Any keys, emails or card numbers in it are fake test values.

# Sample report: DevBox MCP Workstation (fictional)

**Score: 13/100 (grade F)**

| Check | Sub-score |
|---|---|
| Prompt injection exposure | 100/100 |
| Tool permissions | 29/100 |
| Secret & data leakage | 60/100 |
| Agentic risks (multi-agent, memory) | 75/100 |
| Limits, supply chain & audit | 48/100 |

> Lethal trifecta: all three legs present and the outbound channel is not gated.

### [CRITICAL] TP-3 Untrusted input combined with an exfiltration-capable tool

Can read outside content (mcp:web) and send data out (mcp:web) without approval.

Tags: OWASP LLM01, OWASP LLM06, AML.T0051.001, AML.T0057

**Fix:** Break the chain: do not give one agent both untrusted-content access and a send/network tool, or gate the send behind human review and a destination allowlist.

### [CRITICAL] DL-1 Secret or credential in the prompt or config

AWS access key ID found in the tool "mcp:cloud". Evidence (masked): `AKI…**** (20 chars)`

Tags: OWASP LLM02, OWASP LLM07, AML.T0055, AML.T0057

**Fix:** Remove it, rotate the credential now, and keep secrets in a server-side vault. Give the agent a tool that uses the secret on its behalf without ever showing it to the model.

### [CRITICAL] LT-1 Lethal trifecta: private data + untrusted content + external communication

Private data (tool mcp:files), untrusted content (tool mcp:web) and an outbound channel (tool mcp:web) are all reachable, with the outbound channel unguarded.

Tags: OWASP LLM01, OWASP LLM02, OWASP LLM06, AML.T0051.001, AML.T0057

**Fix:** Remove at least one leg of the trifecta. Easiest options: block the outbound channel, remove private-data access from the agent that reads untrusted content, or gate every outbound action behind human approval and a destination allowlist.

### [HIGH] TP-1 High-impact tool without human confirmation

Tool "mcp:files" (file write / delete) has no confirmation or approval step.

Tags: OWASP LLM06, AML.T0053

**Fix:** Require explicit human approval for each call (or a pre-approved, narrowly scoped allowlist). Show the exact command, recipient, path or amount before it runs.

### [HIGH] TP-1 High-impact tool without human confirmation

Tool "mcp:web" (network / HTTP request) has no confirmation or approval step.

Tags: OWASP LLM06, AML.T0053

**Fix:** Require explicit human approval for each call (or a pre-approved, narrowly scoped allowlist). Show the exact command, recipient, path or amount before it runs.

### [HIGH] DL-2 No output filtering or redaction

No output filtering, redaction or link/image allowlisting is described.

Tags: OWASP LLM05, OWASP LLM02, AML.T0057

**Fix:** Add a deterministic output filter: redact secret patterns and PII, block system-prompt text, and restrict markdown images and links to an allowlist of domains.

### [HIGH] MCP-3 MCP filesystem server with a broad root

MCP filesystem server "files" is rooted at a broad path (/).

Tags: OWASP LLM06, AML.T0053

**Fix:** Point filesystem servers at a single project directory, never at /, your home directory, or a drive root.

### [HIGH] MCP-2 Remote MCP server over plain HTTP or without auth

MCP server "tracker" is reached over plain HTTP (tracker.example.net).

Tags: OWASP LLM03, OWASP LLM02, AML.T0010

**Fix:** Use https for remote MCP servers and authenticate with scoped, short-lived tokens. Only connect to servers you trust.

### [MEDIUM] TP-2 High-impact tool without scoping

Tool "mcp:files" (file write / delete) shows no scoping such as an allowlist, sandbox, path or amount limit.

Tags: OWASP LLM06, AML.T0053

**Fix:** Constrain the tool: allowlist commands, domains, recipients and directories; cap amounts; use a least-privilege credential; run shell and file tools in a sandbox with no secrets mounted.

### [MEDIUM] TP-2 High-impact tool without scoping

Tool "mcp:web" (network / HTTP request) shows no scoping such as an allowlist, sandbox, path or amount limit.

Tags: OWASP LLM06, AML.T0053

**Fix:** Constrain the tool: allowlist commands, domains, recipients and directories; cap amounts; use a least-privilege credential; run shell and file tools in a sandbox with no secrets mounted.

### [MEDIUM] MCP-1 MCP server launched from an unpinned package

MCP server "files" runs "npx @modelcontextprotocol/server-filesystem" without a pinned version and with auto-install (-y).

Tags: OWASP LLM03, AML.T0010

**Fix:** Pin MCP server packages to an exact version (or a digest) and avoid auto-install flags like npx -y for unreviewed packages.

### [MEDIUM] MCP-1 MCP server launched from an unpinned package

MCP server "web" runs "uvx mcp-server-fetch" without a pinned version.

Tags: OWASP LLM03, AML.T0010

**Fix:** Pin MCP server packages to an exact version (or a digest) and avoid auto-install flags like npx -y for unreviewed packages.

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

`eyJ2IjoxLCJzIjoxMywiYyI6eyJpbmplY3Rpb24iOjEwMCwicGVybWlzc2lvbnMiOjI5LCJsZWFrYWdlIjo2MCwiYWdlbnRpYyI6NzUsImdvdmVybmFuY2UiOjQ4fSwibiI6eyJwcm9tcHRDaGFycyI6MjQ1LCJ0b29scyI6NCwic2FtcGxlcyI6MCwiYWdlbnRzIjowLCJtY3BTZXJ2ZXJzIjo0fSwiZiI6W1siVFAtMyIsImMiLCJDYW4gcmVhZCBvdXRzaWRlIGNvbnRlbnQgKG1jcDp3ZWIpIGFuZCBzZW5kIGRhdGEgb3V0IChtY3A6d2ViKSB3aXRob3V0IGFwcHJvdmFsLiIsIiJdLFsiREwtMSIsImMiLCJBV1MgYWNjZXNzIGtleSBJRCBmb3VuZCBpbiB0aGUgdG9vbCBcIm1jcDpjbG91ZFwiLiIsIkFLSeKApioqKiogKDIwIGNoYXJzKSJdLFsiTFQtMSIsImMiLCJQcml2YXRlIGRhdGEgKHRvb2wgbWNwOmZpbGVzKSwgdW50cnVzdGVkIGNvbnRlbnQgKHRvb2wgbWNwOndlYikgYW5kIGFuIG91dGJvdW5kIGNoYW5uZWwgKHRvb2wgbWNwOndlYikgYXJlIGFsbCByZWFjaGFibGUsIHdpdGggdGhlIG91dGJvdW5kIGNoYW5uZWwgdW5ndWFyZGVkLiIsIiJdLFsiVFAtMSIsImgiLCJUb29sIFwibWNwOmZpbGVzXCIgKGZpbGUgd3JpdGUgLyBkZWxldGUpIGhhcyBubyBjb25maXJtYXRpb24gb3IgYXBwcm92YWwgc3RlcC4iLCIiXSxbIlRQLTEiLCJoIiwiVG9vbCBcIm1jcDp3ZWJcIiAobmV0d29yayAvIEhUVFAgcmVxdWVzdCkgaGFzIG5vIGNvbmZpcm1hdGlvbiBvciBhcHByb3ZhbCBzdGVwLiIsIiJdLFsiREwtMiIsImgiLCJObyBvdXRwdXQgZmlsdGVyaW5nLCByZWRhY3Rpb24gb3IgbGluay9pbWFnZSBhbGxvd2xpc3RpbmcgaXMgZGVzY3JpYmVkLiIsIiJdLFsiTUNQLTMiLCJoIiwiTUNQIGZpbGVzeXN0ZW0gc2VydmVyIFwiZmlsZXNcIiBpcyByb290ZWQgYXQgYSBicm9hZCBwYXRoICgvKS4iLCIiXSxbIk1DUC0yIiwiaCIsIk1DUCBzZXJ2ZXIgXCJ0cmFja2VyXCIgaXMgcmVhY2hlZCBvdmVyIHBsYWluIEhUVFAgKHRyYWNrZXIuZXhhbXBsZS5uZXQpLiIsIiJdLFsiVFAtMiIsIm0iLCJUb29sIFwibWNwOmZpbGVzXCIgKGZpbGUgd3JpdGUgLyBkZWxldGUpIHNob3dzIG5vIHNjb3Bpbmcgc3VjaCBhcyBhbiBhbGxvd2xpc3QsIHNhbmRib3gsIHBhdGggb3IgYW1vdW50IGxpbWl0LiIsIiJdLFsiVFAtMiIsIm0iLCJUb29sIFwibWNwOndlYlwiIChuZXR3b3JrIC8gSFRUUCByZXF1ZXN0KSBzaG93cyBubyBzY29waW5nIHN1Y2ggYXMgYW4gYWxsb3dsaXN0LCBzYW5kYm94LCBwYXRoIG9yIGFtb3VudCBsaW1pdC4iLCIiXSxbIk1DUC0xIiwibSIsIk1DUCBzZXJ2ZXIgXCJmaWxlc1wiIHJ1bnMgXCJucHggQG1vZGVsY29udGV4dHByb3RvY29sL3NlcnZlci1maWxlc3lzdGVtXCIgd2l0aG91dCBhIHBpbm5lZCB2ZXJzaW9uIGFuZCB3aXRoIGF1dG8taW5zdGFsbCAoLXkpLiIsIiJdLFsiTUNQLTEiLCJtIiwiTUNQIHNlcnZlciBcIndlYlwiIHJ1bnMgXCJ1dnggbWNwLXNlcnZlci1mZXRjaFwiIHdpdGhvdXQgYSBwaW5uZWQgdmVyc2lvbi4iLCIiXSxbIlJMLTEiLCJsIiwiTm8gbWF4aW11bSBudW1iZXIgb2Ygc3RlcHMsIHRvb2wgY2FsbHMsIHRpbWUgb3Igc3BlbmQgaXMgc3RhdGVkLiIsIiJdLFsiQVUtMSIsImwiLCJIaWdoLWltcGFjdCB0b29scyBhcmUgcHJlc2VudCBidXQgbm8gYXVkaXQgbG9nZ2luZyBvZiB0aGVpciBjYWxscyBpcyBkZXNjcmliZWQuIiwiIl1dfQ`
