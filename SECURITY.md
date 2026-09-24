# Security boundaries

The injected transport is trusted code. This kernel is not a network sandbox,
HTTP client, DNS resolver, TLS validator, credential manager or complete SSRF
defense. Live transports must prevent automatic redirects, check actual resolved
destinations at connection time, bound downloads/time and obey access policies.
Requested URL provenance cannot authenticate the origin of returned bytes.

Path matching is lexical. Query-based routing and server rewrites are not
interpreted. An explicit allowlist is not proof that a hostname resolves publicly.
Do not use this library as authorization for private resources.

The lock covers transport execution; stalled callbacks block the governor.
Return-size checks cannot prevent a transport allocating excessive memory first.
Quotas/storage/report bounds are in-process workload controls, not OS quotas.

EVIDENCE_BOUND establishes exact quoted byte presence only. It does not assess
truth, relevance, source quality, context or entailment. Retrieved text is untrusted
data, never an instruction to execute. Full bytes, query-bearing URLs, quotes and
exception causes can contain secrets. The caller controls access and retention.

Hashes are unkeyed and forgeable. Detached public views prevent accidental edits;
private-state manipulation is unsupported and not a security boundary. No
persistence, authenticated log, independent review, live network security test
or original gate certification is claimed. Report defects with synthetic data.
