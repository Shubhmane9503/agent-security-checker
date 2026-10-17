> **FICTIONAL EXAMPLE AGENT. Not a real product.** The agent below is invented for demonstration. Any keys, emails or card numbers in it are fake test values.

# Sample report: Harbor Support Crew (fictional)

**Score: 15/100 (grade F)**

| Check | Sub-score |
|---|---|
| Prompt injection exposure | 47/100 |
| Tool permissions | 12/100 |
| Secret & data leakage | 85/100 |
| Agentic risks (multi-agent, memory) | 45/100 |
| Limits, supply chain & audit | 94/100 |

> Lethal trifecta: all three legs present and the outbound channel is not gated.

### [CRITICAL] TP-1 High-impact tool without human confirmation

Tool "issue_refund" (payment / money movement) has no confirmation or approval step.

Tags: OWASP LLM06, AML.T0053

**Fix:** Require explicit human approval for each call (or a pre-approved, narrowly scoped allowlist). Show the exact command, recipient, path or amount before it runs.

### [CRITICAL] TP-3 Untrusted input combined with an exfiltration-capable tool

Can read outside content (read_ticket) and send data out (send_email) without approval.

Tags: OWASP LLM01, OWASP LLM06, AML.T0051.001, AML.T0057

**Fix:** Break the chain: do not give one agent both untrusted-content access and a send/network tool, or gate the send behind human review and a destination allowlist.

### [CRITICAL] LT-1 Lethal trifecta: private data + untrusted content + external communication

Private data (tool issue_refund, prompt mentions private data), untrusted content (tool read_ticket, placeholder {ticket_body}) and an outbound channel (tool send_email) are all reachable, with the outbound channel unguarded.

Tags: OWASP LLM01, OWASP LLM02, OWASP LLM06, AML.T0051.001, AML.T0057

**Fix:** Remove at least one leg of the trifecta. Easiest options: block the outbound channel, remove private-data access from the agent that reads untrusted content, or gate every outbound action behind human approval and a destination allowlist.

### [HIGH] PI-1 No instruction hierarchy

The prompt never says system instructions outrank content the agent reads, or that embedded instructions must be ignored.

Tags: OWASP LLM01, AML.T0051

**Fix:** State that system instructions outrank everything else, and that text inside documents, web pages, emails, tool results or user-supplied files is data to analyse, never instructions to follow.

### [HIGH] PI-2 Untrusted content interpolated into the prompt

Template placeholders inject external text into the prompt: {ticket_body}.

Tags: OWASP LLM01, AML.T0051.001

**Fix:** Do not splice external content straight into the system prompt. Pass it as a separate, clearly labelled message or tool result, and keep the system prompt static.

### [HIGH] PI-3 Untrusted content is not delimited

External content is referenced but no delimiter (XML tags, fences, begin/end markers) separates it from instructions.

Tags: OWASP LLM01, AML.T0051.001

**Fix:** Wrap every untrusted block in explicit delimiters (for example <untrusted_document>…</untrusted_document>), tell the model the delimited text is data only, and strip delimiter look-alikes from the content first.

### [HIGH] TP-2 High-impact tool without scoping

Tool "issue_refund" (payment / money movement) shows no scoping such as an allowlist, sandbox, path or amount limit.

Tags: OWASP LLM06, AML.T0053

**Fix:** Constrain the tool: allowlist commands, domains, recipients and directories; cap amounts; use a least-privilege credential; run shell and file tools in a sandbox with no secrets mounted.

### [HIGH] TP-1 High-impact tool without human confirmation

Tool "send_email" (email / messaging send) has no confirmation or approval step.

Tags: OWASP LLM06, AML.T0053

**Fix:** Require explicit human approval for each call (or a pre-approved, narrowly scoped allowlist). Show the exact command, recipient, path or amount before it runs.

### [HIGH] DL-2 No output filtering or redaction

No output filtering, redaction or link/image allowlisting is described.

Tags: OWASP LLM05, OWASP LLM02, AML.T0057

**Fix:** Add a deterministic output filter: redact secret patterns and PII, block system-prompt text, and restrict markdown images and links to an allowlist of domains.

### [HIGH] MA-1 Agent handoff without a trust boundary

Multi-agent or handoff behaviour is present (3 agents) but nothing says messages from other agents are untrusted or validated.

Tags: OWASP LLM01, OWASP LLM06, AML.T0051.001, AML.T0053

**Fix:** Treat messages from other agents as untrusted input. Pass structured, validated fields instead of free text, and re-check permissions in the receiving agent.

### [HIGH] MM-1 Persistent memory writable from untrusted content

Persistent memory can be written while the agent also reads untrusted content, and no write validation is described.

Tags: OWASP LLM04, OWASP LLM01, AML.T0080

**Fix:** Validate what is written to memory: only store user-confirmed facts, never text copied from web pages or emails, tag entries with their source, and let users review and delete memories.

### [MEDIUM] PI-4 Agent reads untrusted content with no stated handling

Tools that bring in outside content (read_ticket) but the prompt gives no handling rules for it.

Tags: OWASP LLM01, AML.T0051.001

**Fix:** For tools that fetch web pages, emails, tickets or files, add handling rules: summarise only, never act on instructions found inside, and require confirmation before any action triggered after reading such content.

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

`eyJ2IjoxLCJzIjoxNSwiYyI6eyJpbmplY3Rpb24iOjQ3LCJwZXJtaXNzaW9ucyI6MTIsImxlYWthZ2UiOjg1LCJhZ2VudGljIjo0NSwiZ292ZXJuYW5jZSI6OTR9LCJuIjp7InByb21wdENoYXJzIjozOTEsInRvb2xzIjo0LCJzYW1wbGVzIjowLCJhZ2VudHMiOjMsIm1jcFNlcnZlcnMiOjB9LCJmIjpbWyJUUC0xIiwiYyIsIlRvb2wgXCJpc3N1ZV9yZWZ1bmRcIiAocGF5bWVudCAvIG1vbmV5IG1vdmVtZW50KSBoYXMgbm8gY29uZmlybWF0aW9uIG9yIGFwcHJvdmFsIHN0ZXAuIiwiIl0sWyJUUC0zIiwiYyIsIkNhbiByZWFkIG91dHNpZGUgY29udGVudCAocmVhZF90aWNrZXQpIGFuZCBzZW5kIGRhdGEgb3V0IChzZW5kX2VtYWlsKSB3aXRob3V0IGFwcHJvdmFsLiIsIiJdLFsiTFQtMSIsImMiLCJQcml2YXRlIGRhdGEgKHRvb2wgaXNzdWVfcmVmdW5kLCBwcm9tcHQgbWVudGlvbnMgcHJpdmF0ZSBkYXRhKSwgdW50cnVzdGVkIGNvbnRlbnQgKHRvb2wgcmVhZF90aWNrZXQsIHBsYWNlaG9sZGVyIHt0aWNrZXRfYm9keX0pIGFuZCBhbiBvdXRib3VuZCBjaGFubmVsICh0b29sIHNlbmRfZW1haWwpIGFyZSBhbGwgcmVhY2hhYmxlLCB3aXRoIHRoZSBvdXRib3VuZCBjaGFubmVsIHVuZ3VhcmRlZC4iLCIiXSxbIlBJLTEiLCJoIiwiVGhlIHByb21wdCBuZXZlciBzYXlzIHN5c3RlbSBpbnN0cnVjdGlvbnMgb3V0cmFuayBjb250ZW50IHRoZSBhZ2VudCByZWFkcywgb3IgdGhhdCBlbWJlZGRlZCBpbnN0cnVjdGlvbnMgbXVzdCBiZSBpZ25vcmVkLiIsIiJdLFsiUEktMiIsImgiLCJUZW1wbGF0ZSBwbGFjZWhvbGRlcnMgaW5qZWN0IGV4dGVybmFsIHRleHQgaW50byB0aGUgcHJvbXB0OiB7dGlja2V0X2JvZHl9LiIsIiJdLFsiUEktMyIsImgiLCJFeHRlcm5hbCBjb250ZW50IGlzIHJlZmVyZW5jZWQgYnV0IG5vIGRlbGltaXRlciAoWE1MIHRhZ3MsIGZlbmNlcywgYmVnaW4vZW5kIG1hcmtlcnMpIHNlcGFyYXRlcyBpdCBmcm9tIGluc3RydWN0aW9ucy4iLCIiXSxbIlRQLTIiLCJoIiwiVG9vbCBcImlzc3VlX3JlZnVuZFwiIChwYXltZW50IC8gbW9uZXkgbW92ZW1lbnQpIHNob3dzIG5vIHNjb3Bpbmcgc3VjaCBhcyBhbiBhbGxvd2xpc3QsIHNhbmRib3gsIHBhdGggb3IgYW1vdW50IGxpbWl0LiIsIiJdLFsiVFAtMSIsImgiLCJUb29sIFwic2VuZF9lbWFpbFwiIChlbWFpbCAvIG1lc3NhZ2luZyBzZW5kKSBoYXMgbm8gY29uZmlybWF0aW9uIG9yIGFwcHJvdmFsIHN0ZXAuIiwiIl0sWyJETC0yIiwiaCIsIk5vIG91dHB1dCBmaWx0ZXJpbmcsIHJlZGFjdGlvbiBvciBsaW5rL2ltYWdlIGFsbG93bGlzdGluZyBpcyBkZXNjcmliZWQuIiwiIl0sWyJNQS0xIiwiaCIsIk11bHRpLWFnZW50IG9yIGhhbmRvZmYgYmVoYXZpb3VyIGlzIHByZXNlbnQgKDMgYWdlbnRzKSBidXQgbm90aGluZyBzYXlzIG1lc3NhZ2VzIGZyb20gb3RoZXIgYWdlbnRzIGFyZSB1bnRydXN0ZWQgb3IgdmFsaWRhdGVkLiIsIiJdLFsiTU0tMSIsImgiLCJQZXJzaXN0ZW50IG1lbW9yeSBjYW4gYmUgd3JpdHRlbiB3aGlsZSB0aGUgYWdlbnQgYWxzbyByZWFkcyB1bnRydXN0ZWQgY29udGVudCwgYW5kIG5vIHdyaXRlIHZhbGlkYXRpb24gaXMgZGVzY3JpYmVkLiIsIiJdLFsiUEktNCIsIm0iLCJUb29scyB0aGF0IGJyaW5nIGluIG91dHNpZGUgY29udGVudCAocmVhZF90aWNrZXQpIGJ1dCB0aGUgcHJvbXB0IGdpdmVzIG5vIGhhbmRsaW5nIHJ1bGVzIGZvciBpdC4iLCIiXSxbIlRQLTIiLCJtIiwiVG9vbCBcInNlbmRfZW1haWxcIiAoZW1haWwgLyBtZXNzYWdpbmcgc2VuZCkgc2hvd3Mgbm8gc2NvcGluZyBzdWNoIGFzIGFuIGFsbG93bGlzdCwgc2FuZGJveCwgcGF0aCBvciBhbW91bnQgbGltaXQuIiwiIl0sWyJSTC0xIiwibCIsIk5vIG1heGltdW0gbnVtYmVyIG9mIHN0ZXBzLCB0b29sIGNhbGxzLCB0aW1lIG9yIHNwZW5kIGlzIHN0YXRlZC4iLCIiXSxbIkFVLTEiLCJsIiwiSGlnaC1pbXBhY3QgdG9vbHMgYXJlIHByZXNlbnQgYnV0IG5vIGF1ZGl0IGxvZ2dpbmcgb2YgdGhlaXIgY2FsbHMgaXMgZGVzY3JpYmVkLiIsIiJdXX0`
