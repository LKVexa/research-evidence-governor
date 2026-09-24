# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S028-P001 / 0.1.1-partial / run-0001 / product.
Reviewed policy/URL checks, capture lifecycle, quota concurrency, snapshot
integrity and claim binding. Original source remains separate.

## Repaired findings

- Mutable allowlists/path rules and loosely typed quotas could change policy.
  Policies are validated, frozen and independently reconstructed by the governor.
- URL parsing accepted credentials, alternate ports, controls and ambiguous
  encodings. Strict authority/URL syntax plus bounded normalized path checks
  refuse these cases. This does not implement DNS/TLS/redirect enforcement;
  the trusted transport contract now makes that boundary explicit.
- Counts advanced only after transport success, failures disappeared from the
  ledger and concurrent calls could race. Serialized attempts charge before
  dispatch, record failure states and refuse recursive fetches.
- Arbitrary transport outputs were silently stringified. Only bounded exact
  bytes are accepted; storage/ledger/snapshot capacities fail closed and ledger
  overflow is counted without unbounded record growth.
- Public mutable snapshots/ledger and content-only checks left metadata, removals
  and quota state unprotected. Detached public views, snapshot record digests,
  content hashes and a full state seal now detect consistency changes. Claims and
  captures verify state; corrupt callback state is not resealed on return/error.
- SUPPORTED was asserted merely from citations or any one quote, without
  checking snapshot integrity. New statuses separate exact evidence binding
  from unverified citations; every quote and every cited source must participate.
  Byte spans, complete metadata and report digests make bindings reviewable.
  No semantic truth/support assertion remains.
- Claim size, scan work and output were unbounded. Strict input, text, quote-scan,
  match-count and report-size budgets now apply before returning a report.

## Verification and compatibility

18 baseline tests passed; the inherited source-inspection fixture leaked an open
file, now replaced with an explicit UTF-8 Path read. 59 source/installed-wheel tests
pass after changes, including 41 new cases for URL ambiguity/encoding, frozen
policy, charged/logged failures, byte/storage/ledger caps, concurrent quota limits,
callback recursion/corruption, full provenance/state tamper checks, complete quote
coverage, UTF-8 byte offsets and claim/scan/output budgets.

Inherited expectations migrated from SUPPORTED/supported to
EVIDENCE_BOUND/evidence_bound. The tamper fixture now deliberately edits private
state because public snapshots are detached; the version assertion advanced.
No assertion was weakened to hide missing semantic assessment.

CHECK_RUNS.json records current evidence and BASELINE_CHECK_RUNS.json preserves
historical evidence. CI covers Linux Python 3.10/3.12/3.14 and Windows 3.12.
All network behavior remains untested: fixtures are offline, with no third-party
runtime packages. No build-tool vulnerability scan, independent security audit
or 992-item program certification is claimed.

Version 0.1.1-partial -> 0.1.2a1; snapshot/claim schemas v2. Added packaging,
pinned-action CI, README, security guidance and Apache 2.0 LICENSE/NOTICE naming
RUSSELL PHILIP SMITHSON. No third-party source is vendored.

## Primary references

- [Python URL parsing](https://docs.python.org/3/library/urllib.parse.html):
  parsing is not validation and can strip URL control characters.
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html):
  destination checks, DNS risks and redirect handling exceed this lexical kernel.
