# 0.1.2a1 — 2026-09-23

- Validate immutable URL policies and refuse ambiguous authorities/paths.
- Serialize captures, charge failed attempts and record transport failures.
- Bound storage and ledgers; expose detached views and verify full state.
- Replace semantic-support claims with exact quote binding and byte offsets.
- Add claim/work/output budgets, 41 regressions, packaging and CI.
- Include README and Apache 2.0 LICENSE/NOTICE; live transport and certification remain open.

# Changelog — E07 Public-Network Research governed kernel (JY-S028-P001)

## 0.1.1-partial — 2026-09-14 (audit A024, maintenance run-0001)

Baseline fingerprint: build-0001 `product.zip`
sha256 `a2687aa84c95d93834ad99262c25c60654c393d6ee49d10b212b8287f43025e4`
(6733 bytes), kernel `0.1.0-partial`. All 4 findings reproduced on the
baseline before fixing (probe output in `audit/`). No live network is
used anywhere; the transport remains operator-injected and the test
suite stays fully offline.

- **A024-F1 (high, policy bypass)** — deny-path rules were a
  case-sensitive substring test on the raw path, so
  `/Admin/config`, `/ADMIN` and percent-encoded `/%61dmin/config`
  fetched successfully past the `/admin` rule. Fixed: the path is
  percent-decoded twice (defeats double-encoding) and casefolded, and
  deny fragments are casefolded, before matching.
- **A024-F2 (high, evidence bypass)** — an empty string in a claim's
  `quotes` matched any snapshot content (`b"" in content` is always
  True), letting a fabricated claim come back SUPPORTED. Fixed:
  quotes must be non-empty strings; violations raise `ValueError`.
- **A024-F3 (medium, error contract)** — malformed claims leaked bare
  `KeyError: 'text'` / `AttributeError` out of `bind_claims`. Fixed:
  claim shape is validated and violations raise `ValueError` with a
  clear message.
- **A024-F4 (medium, ledger integrity)** — `access_report()` returned
  refused ledger entries by reference; mutating the report forged the
  governor's audit ledger. Fixed: refused entries are deep-copied.
- Added native `__version__` (aliases `VERSION`), 5 regression tests
  (18 total), README version line.

Compatibility: repairs only — no public API removed or renamed.
Callers that relied on the buggy behaviors above (deny-path bypass,
empty-quote support, bare KeyError, aliased report) will see the
strengthened contract. Rollback: redeploy baseline build-0001
`product.zip` (sha256 above).
