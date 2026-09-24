# Research Evidence Governor

**0.1.2a1 — experimental partial candidate, JY-S028-P001 / E07**

An in-memory policy and evidence layer around a trusted, injected transport.
It validates requested URLs, budgets capture attempts, preserves snapshots and
binds literal quotes to source bytes. It performs no network I/O itself and does
not establish that a research claim is true.

Python 3.10+; no third-party runtime packages.

## Offline example

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from e07.core import ResearchPolicy, ResearchGovernor

pages = {"https://docs.example.org/spec": b"The default port is 8443."}
governor = ResearchGovernor(
    ResearchPolicy(["docs.example.org"], per_domain_quota=5),
    lambda url: pages[url],
)
snapshot = governor.fetch("https://docs.example.org/spec")
report = governor.bind_claims([{
    "text": "The default port is 8443.",
    "cites": [snapshot["snapshot_id"]],
    "quotes": ["port is 8443"],
}])
assert report["claims"][0]["status"] == "EVIDENCE_BOUND"
assert governor.verify_snapshots()["verdict"] == "PASS"
~~~

## Policy and URL checks

ResearchPolicy takes an explicit list/tuple of 1..64 ASCII DNS names, optional
denied path substrings and a strict integer per-domain quota of 1..1000
(default 20). Names lowercase and match exactly; subdomains are not implicit.
Wildcard, IP literal, port-bearing, trailing-dot and single-label entries are
refused. Host syntax requires a 2..63-letter final label; internationalized top
level domains are outside this candidate. This syntax check does not prove a
domain resolves to public addresses.

Policies are frozen and copied into the governor. Default denied path fragments:
/login, /account, /admin, /private. Passing an explicit empty list disables those
path rules. Up to 32 bounded, slash-prefixed rules are accepted and normalized.

URLs are ASCII, at most 4096 characters, HTTPS only, with no whitespace, raw
controls, backslashes, userinfo or fragments. Only the exact hostname and optional
literal :443 authority are accepted. Scheme/host case and :443 normalize before
transport; empty paths become /. Query text remains present.

For deny matching, paths undergo at most four rounds of percent decoding and
Unicode NFKC normalization, then case folding and repeated-slash folding.
Invalid/deep percent escapes, residual percent signs, invalid UTF-8, dot segments,
semicolons, decoded backslashes and controls are refused. Even legitimate literal
percent paths can therefore be refused. The transport receives the original
encoded path, with normalized scheme/host/port, not the decoded policy-check path.

These are conservative lexical rules, not application authorization. Query
parameters, server-specific routing, aliases and arbitrary rewrite behavior are
not interpreted. Do not rely on a path denylist to protect private resources.

## Transport contract and limits

The callable receives one canonical URL and must return exact bytes. It is trusted
to fetch only that destination. A live transport must disable automatic redirects;
an intended redirect requires a separate governed fetch of the new URL. It must
validate TLS, resolve and enforce approved public destination addresses at connection
time, handle DNS rebinding/proxies safely, avoid implicit credentials, honor access
rules/robots where applicable, and bound download size and time before returning.

The kernel cannot observe or prevent a transport fetching a different host,
following redirects, contacting private addresses, writing files or returning
fabricated data. It does not provide an HTTP client, DNS/TLS validation or complete
SSRF defense. No live network behavior was exercised in this release.

An RLock serializes operations, including the transport call. Reentrant fetches
from the callback are refused; ordinary concurrent attempts cannot race quotas.
A hung transport blocks the governor and can exceed any desired time/memory
budget. Cancellation/network deadlines belong to the trusted transport.

Each dispatched attempt consumes per-domain lifetime quota before transport,
including failures, bad return types and oversized responses. Policy refusals
do not consume domain quota. A successful capture gets a new snapshot ID even
when bytes repeat. No successful snapshot is overwritten.

Limits per governor: 2000 ledger entries, 250 snapshots, 1 MiB per returned body,
16 MiB retained content. Full storage refuses before dispatch; a response that
would exceed remaining bytes fails after dispatch and remains charged. The body
limit is a return-value check, not a bound on the transport's allocation.
At ledger capacity, requests are refused before dispatch and counted in
unrecorded_capacity_refusals without retaining individual records.

## Snapshots, failures and integrity

Snapshot schema e07/snapshot/v2 records requested canonical URL, capture time
after transport returns, content and content_digest. record_digest binds its
schema, ID, URL, timestamp and content digest. URL/time are local provenance
claims, not proof of actual remote origin or synchronized time.

The private store has a state digest binding policy, ledger, quota counts,
snapshot metadata, ID sequence and byte totals. Content hashes and the state
digest are checked before fetches, claim binding and access reports. Tampering
causes IntegrityError; verify_snapshots reports FAIL. Corruption during a transport
callback is not silently resealed, including when that callback throws.

Public snapshots and ledger properties return detached copies. Bytes are
immutable. These are in-process consistency measures, not protection against a
process owner rewriting private state and hashes. There is no disk persistence,
cross-process locking, append-only external log, signature or authenticated time.

Ledger status distinguishes REFUSED, PENDING, CAPTURED, TRANSPORT_ERROR,
RESPONSE_REFUSED and CAPTURE_ERROR. PolicyRefused means no transport dispatch;
CaptureFailed means dispatch occurred but capture failed. Transport exceptions
are chained, while ledger reasons omit their raw messages. Interrupted callbacks
are logged and re-raised. access_report exposes dispatch/capture/failure counts;
allowed means policy-approved dispatch, not successful capture.

Invalid/refused raw URLs are represented by a digest when bounded, avoiding
userinfo in refusal logs. Successful snapshot/ledger URLs retain query strings.
Avoid passing secrets in URLs: content, quotes, reports, URLs and exception causes
can contain private data; hashes also expose equality and guessing opportunities.

## Quote binding, not truth assessment

bind_claims accepts at most 100 dictionaries with text, optional cites and quotes.
Text is nonblank, up to 4096 characters. Cites are up to 32 unique snapshot IDs;
quotes are up to 32 unique nonblank strings, each up to 4096 characters. Combined
claim/quote text is capped at 256 KiB UTF-8. Unknown fields, malformed Unicode
and duplicates are refused with ValueError.

- EVIDENCE_BOUND: every quote occurs in at least one cited intact snapshot and
  every citation has at least one matching quote.
- CITED_UNVERIFIED: all citations exist, but no quotes were supplied.
- UNSUPPORTED: citations are absent/missing, some quotes do not occur, or some
  citations have no matched quote.

Matching is exact UTF-8 byte substring presence, with no decoding, normalization,
parsing, word-boundary rule, relevance evaluation or semantic entailment. Binary
content can contain the same byte sequence. A false claim paired with an unrelated
real quote can still be EVIDENCE_BOUND; human/source evaluation remains necessary.

The first occurrence of each quote/source pair is reported with zero-based,
half-open byte offsets, quote index and snapshot ID. Evidence includes URL,
capture time, content digest and record digest. Claims/reports have unsigned
digests binding text, citations, quote bindings and the store state. Report schema
is e07/claim-report/v2; there is no SUPPORTED verdict or supported count.

Per report, quote scans are budgeted as source byte lengths times quote counts,
at most 64 MiB. At most 4096 matches and 4 MiB JSON before adding report_digest
are returned. Over-budget matching raises ValueError without partial reports
or state mutation. These limits are not OS-level resource isolation.

## Verification and migration

59 tests: 18 inherited checks plus 41 new regressions. Source and installed-wheel
evidence: [CHECK_RUNS](docs/CHECK_RUNS.json). CI covers Linux 3.10/3.12/3.14 and
Windows 3.12. All transports in tests are offline fixtures. See [AUDIT](docs/AUDIT.md)
and [SECURITY](SECURITY.md).

0.1.1-partial -> 0.1.2a1 changes URL/policy strictness, quota charging, transport
error behavior, mutable public views, claim statuses and snapshot/report schemas.
Update consumers for EVIDENCE_BOUND/CITED_UNVERIFIED and evidence_bound counts.
Do not compare old/new digests. No stored-record migration or live transport is
provided. The original 992-item program, governance gates, content extraction,
summarization, remote attestation and formal certification remain open.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party source is vendored; see [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md).
