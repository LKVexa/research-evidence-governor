"""Offline policy and evidence bookkeeping around a trusted injected transport."""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import math
import re
import threading
import time
import unicodedata
from urllib.parse import unquote, urlsplit, urlunsplit

VERSION = "0.1.2a1"
__version__ = VERSION
MAX_REQUESTS = 2000
MAX_SNAPSHOTS = 250
MAX_CONTENT_BYTES = 1048576
MAX_STORE_BYTES = 16777216
MAX_QUOTE_SCAN_BYTES = 67108864
MAX_BINDINGS = 4096
MAX_REPORT_BYTES = 4194304
DEFAULT_DENIED = ("/login", "/account", "/admin", "/private")


class PolicyRefused(Exception):
    pass


class CaptureFailed(Exception):
    pass


class IntegrityError(Exception):
    pass


def _digest(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _hash(obj):
    return _digest(json.dumps(obj, sort_keys=True, ensure_ascii=True,
                              allow_nan=False, separators=(",", ":")).encode())


def _domain(value):
    if type(value) is not str or not 1 <= len(value) <= 253 or not value.isascii():
        raise ValueError("allowlist domains must be ASCII DNS names")
    value = value.lower()
    labels = value.split(".")
    if (len(labels) < 2 or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise ValueError("allowlist requires full DNS names without ports, wildcards or IP literals")
    return value


def _path(value):
    for _ in range(4):
        value = unicodedata.normalize("NFKC", value)
        if "%" not in value:
            break
        if re.search(r"%(?![0-9A-Fa-f]{2})", value):
            raise ValueError("invalid percent encoding")
        value = unquote(value, encoding="utf-8", errors="strict")
    value = unicodedata.normalize("NFKC", value).casefold()
    if ("%" in value or "\\" in value or ";" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(segment in (".", "..") for segment in value.split("/"))):
        raise ValueError("ambiguous or deeply encoded path")
    return re.sub("/+", "/", value)


@dataclass(frozen=True, init=False)
class ResearchPolicy:
    allowed: frozenset
    deny_paths: tuple
    quota: int

    def __init__(self, allowed_domains, deny_path_substrings=None, per_domain_quota=20):
        if type(allowed_domains) not in (list, tuple) or not 1 <= len(allowed_domains) <= 64:
            raise ValueError("an explicit list of 1..64 domains is required")
        allowed = frozenset(_domain(d) for d in allowed_domains)
        denied = DEFAULT_DENIED if deny_path_substrings is None else deny_path_substrings
        if type(denied) not in (tuple, list) or len(denied) > 32:
            raise ValueError("deny paths must be a list/tuple of at most 32 rules")
        rules = []
        for item in denied:
            if type(item) is not str or not 1 <= len(item) <= 256 or not item.startswith("/"):
                raise ValueError("deny rules must be bounded absolute path substrings")
            rules.append(_path(item))
        if type(per_domain_quota) is not int or not 1 <= per_domain_quota <= 1000:
            raise ValueError("per-domain quota must be an integer in 1..1000")
        object.__setattr__(self, "allowed", allowed)
        object.__setattr__(self, "deny_paths", tuple(sorted(set(rules))))
        object.__setattr__(self, "quota", per_domain_quota)


def _policy_record(policy):
    return {"allowed_domains": sorted(policy.allowed), "deny_paths": list(policy.deny_paths),
            "per_domain_quota": policy.quota}


def _timestamp():
    stamp = time.time()
    if not math.isfinite(stamp):
        raise RuntimeError("invalid host timestamp")
    return stamp


def _snapshot_hash(snapshot):
    return _hash({k: v for k, v in snapshot.items() if k not in ("content", "record_digest")})


class ResearchGovernor:
    """Serialize bounded captures around a trusted callable(url)->bytes.

    The transport must disable redirects, enforce TLS/public destination checks
    and bound bytes/time before returning. This kernel cannot enforce network
    behavior or authenticate what URL actually supplied the returned bytes.
    """
    def __init__(self, policy, transport):
        if type(policy) is not ResearchPolicy or not callable(transport):
            raise ValueError("ResearchPolicy and callable transport are required")
        # Reconstruct, both validating and isolating the supplied policy.
        self._policy = ResearchPolicy(list(policy.allowed), list(policy.deny_paths), policy.quota)
        self._transport = transport
        self._lock = threading.RLock()
        self._busy = False
        self._ledger = []
        self._snapshots = {}
        self._counts = {}
        self._next_snapshot = 0
        self._stored_bytes = 0
        self._overflow_refusals = 0
        self._seal = self._state_hash()

    @property
    def policy(self):
        return self._policy

    @property
    def ledger(self):
        with self._lock:
            return copy.deepcopy(self._ledger)

    @property
    def snapshots(self):
        with self._lock:
            return copy.deepcopy(self._snapshots)

    def _state_hash(self):
        return _hash({
            "policy": _policy_record(self._policy), "ledger": self._ledger,
            "snapshots": {key: {k: v for k, v in snap.items() if k != "content"}
                          for key, snap in self._snapshots.items()},
            "counts": self._counts, "next_snapshot": self._next_snapshot,
            "stored_bytes": self._stored_bytes, "overflow_refusals": self._overflow_refusals,
        })

    def _integrity(self):
        tampered = []
        try:
            for key, snapshot in self._snapshots.items():
                if (type(snapshot) is not dict or set(snapshot) != {
                        "schema", "snapshot_id", "url", "captured_at", "content",
                        "content_digest", "record_digest"}
                        or key != snapshot["snapshot_id"]
                        or type(snapshot["content"]) is not bytes
                        or _digest(snapshot["content"]) != snapshot["content_digest"]
                        or _snapshot_hash(snapshot) != snapshot["record_digest"]):
                    tampered.append(key)
            if self._state_hash() != self._seal:
                tampered.append("state")
        except (TypeError, ValueError, KeyError, AttributeError, OverflowError):
            tampered.append("state")
        return tampered

    def _require_integrity(self):
        if self._integrity():
            raise IntegrityError("evidence, ledger, quota or policy integrity failed")

    def verify_snapshots(self):
        with self._lock:
            tampered = self._integrity()
            return {"schema": "e07/integrity/v2", "snapshots": len(self._snapshots),
                    "tampered": tampered, "verdict": "FAIL" if tampered else "PASS"}

    def _check(self, url):
        if type(url) is not str or not 1 <= len(url) <= 4096 or not url.isascii():
            raise PolicyRefused("URL must be bounded ASCII with percent-encoded Unicode paths")
        if any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
            raise PolicyRefused("URL whitespace, control characters and backslashes are refused")
        try:
            parsed = urlsplit(url)
            if parsed.scheme != "https":
                raise PolicyRefused("https only")
            if parsed.username is not None or parsed.password is not None or "#" in url:
                raise PolicyRefused("URL userinfo and fragments are refused")
            host = _domain(parsed.hostname or "")
            if parsed.netloc.lower() not in (host, host + ":443"):
                raise PolicyRefused("only the canonical hostname and optional port 443 are accepted")
            if host not in self._policy.allowed:
                raise PolicyRefused("domain is not on the allowlist")
            path = _path(parsed.path or "/")
        except (ValueError, UnicodeError) as exc:
            raise PolicyRefused("malformed or ambiguous URL") from exc
        if any(rule in path for rule in self._policy.deny_paths):
            raise PolicyRefused("path contains a denied substring")
        if self._counts.get(host, 0) >= self._policy.quota:
            raise PolicyRefused("per-domain quota exhausted")
        canonical = urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))
        return host, canonical

    def fetch(self, url):
        with self._lock:
            self._require_integrity()
            if len(self._ledger) >= MAX_REQUESTS:
                self._overflow_refusals += 1
                self._seal = self._state_hash()
                raise PolicyRefused("request ledger capacity exhausted; counted without individual record")
            entry = {"request_id": len(self._ledger), "requested_at": _timestamp(),
                     "allowed": False, "status": "REFUSED"}
            # Never retain userinfo or arbitrary raw invalid objects in refusal records.
            if type(url) is str and len(url) <= 4096:
                entry["input_digest"] = _digest(url.encode("utf-8", errors="surrogatepass"))
            try:
                if self._busy:
                    raise PolicyRefused("reentrant fetch from transport refused")
                if len(self._snapshots) >= MAX_SNAPSHOTS or self._stored_bytes >= MAX_STORE_BYTES:
                    raise PolicyRefused("snapshot storage capacity exhausted")
                host, canonical = self._check(url)
            except PolicyRefused as exc:
                entry["reason"] = str(exc)
                self._ledger.append(entry)
                self._seal = self._state_hash()
                raise
            # Every dispatched attempt consumes quota, even when transport fails.
            self._counts[host] = self._counts.get(host, 0) + 1
            entry.update({"allowed": True, "status": "PENDING", "url": canonical, "domain": host})
            self._ledger.append(entry)
            self._seal = self._state_hash()
            self._busy = True
            can_commit = False
            try:
                try:
                    content = self._transport(canonical)
                except BaseException as exc:
                    self._require_integrity()
                    can_commit = True
                    entry["status"] = "TRANSPORT_ERROR"
                    entry["reason"] = "transport failed"
                    if isinstance(exc, Exception):
                        raise CaptureFailed("transport failed") from exc
                    raise
                # Transport runs inside the lock but may call back into this object.
                self._require_integrity()
                can_commit = True
                if type(content) is not bytes or len(content) > MAX_CONTENT_BYTES:
                    entry["status"] = "RESPONSE_REFUSED"
                    entry["reason"] = "transport must return exact bytes within 1 MiB"
                    raise CaptureFailed(entry["reason"])
                if self._stored_bytes + len(content) > MAX_STORE_BYTES:
                    entry["status"] = "RESPONSE_REFUSED"
                    entry["reason"] = "total content budget exceeded"
                    raise CaptureFailed(entry["reason"])
                ident = f"snap-{self._next_snapshot:04d}"
                snapshot = {"schema": "e07/snapshot/v2", "snapshot_id": ident,
                            "url": canonical, "captured_at": _timestamp(),
                            "content": content, "content_digest": _digest(content)}
                snapshot["record_digest"] = _snapshot_hash(snapshot)
                self._snapshots[ident] = snapshot
                self._next_snapshot += 1
                self._stored_bytes += len(content)
                entry.update({"status": "CAPTURED", "snapshot_id": ident,
                              "content_digest": snapshot["content_digest"],
                              "record_digest": snapshot["record_digest"]})
                return {"snapshot_id": ident, "content_digest": snapshot["content_digest"],
                        "record_digest": snapshot["record_digest"], "bytes": len(content)}
            finally:
                self._busy = False
                # Never seal preexisting corruption detected after transport callbacks.
                if can_commit:
                    if entry["status"] == "PENDING":
                        entry["status"] = "CAPTURE_ERROR"
                        entry["reason"] = "capture did not complete"
                    self._seal = self._state_hash()

    def bind_claims(self, claims):
        """Bind exact quote bytes, never claim semantic entailment or truth."""
        clean = _claims(claims)
        with self._lock:
            self._require_integrity()
            out = []
            scanned = binding_count = 0
            for claim in clean:
                row = {"text": claim["text"], "claim_digest": _hash(claim), "status": "UNSUPPORTED"}
                cites, quotes = claim["cites"], claim["quotes"]
                missing = [s for s in cites if s not in self._snapshots]
                if not cites:
                    row["reason"] = "no citations"
                elif missing:
                    row["reason"] = "cited snapshots not in store"
                    row["missing"] = missing
                elif not quotes:
                    row["status"] = "CITED_UNVERIFIED"
                    row["reason"] = "citations exist but no quoted evidence was supplied"
                else:
                    scanned += sum(len(self._snapshots[s]["content"]) for s in cites) * len(quotes)
                    if scanned > MAX_QUOTE_SCAN_BYTES:
                        raise ValueError("quote matching exceeds the 64 MiB scan budget")
                    bindings, matched_quotes, matched_cites = [], set(), set()
                    for q, quote in enumerate(quotes):
                        encoded = quote.encode()
                        for ident in cites:
                            snap = self._snapshots[ident]
                            start = snap["content"].find(encoded)
                            if start >= 0:
                                binding_count += 1
                                if binding_count > MAX_BINDINGS:
                                    raise ValueError("claim report exceeds 4096 quote bindings")
                                matched_quotes.add(q)
                                matched_cites.add(ident)
                                bindings.append({"quote_index": q, "snapshot_id": ident,
                                                 "byte_start": start, "byte_end": start + len(encoded)})
                    if len(matched_quotes) != len(quotes):
                        row["reason"] = "one or more quotes not present in cited snapshots"
                    elif len(matched_cites) != len(cites):
                        row["reason"] = "one or more citations have no matched quote"
                    else:
                        row["status"] = "EVIDENCE_BOUND"
                        row["quotes"] = quotes
                        row["bindings"] = bindings
                if cites and not missing:
                    row["evidence"] = [
                        {k: self._snapshots[ident][k] for k in
                         ("snapshot_id", "url", "captured_at", "content_digest", "record_digest")}
                        for ident in cites]
                out.append(row)
            report = {"schema": "e07/claim-report/v2", "kernel_version": VERSION,
                      "claims": out, "store_digest": self._seal,
                      "evidence_bound": sum(c["status"] == "EVIDENCE_BOUND" for c in out),
                      "cited_unverified": sum(c["status"] == "CITED_UNVERIFIED" for c in out),
                      "unsupported": sum(c["status"] == "UNSUPPORTED" for c in out),
                      "note": "Exact quote presence and source consistency only; no truth or entailment assessment."}
            if len(json.dumps(report, ensure_ascii=True, allow_nan=False).encode()) > MAX_REPORT_BYTES:
                raise ValueError("claim report exceeds 4 MiB JSON budget")
            report["report_digest"] = _hash(report)
            return report

    def access_report(self):
        with self._lock:
            self._require_integrity()
            return {"total_requests": len(self._ledger) + self._overflow_refusals,
                    "recorded_requests": len(self._ledger),
                    "unrecorded_capacity_refusals": self._overflow_refusals,
                    "allowed": sum(e["allowed"] for e in self._ledger),
                    "captured": sum(e["status"] == "CAPTURED" for e in self._ledger),
                    "transport_failed": sum(e["status"] == "TRANSPORT_ERROR" for e in self._ledger),
                    "capture_failed": sum(e["allowed"] and e["status"] not in ("CAPTURED", "PENDING")
                                          for e in self._ledger),
                    "pending": sum(e["status"] == "PENDING" for e in self._ledger),
                    "refused": copy.deepcopy([e for e in self._ledger if not e["allowed"]]),
                    "per_domain_counts": dict(self._counts), "stored_bytes": self._stored_bytes,
                    "state_digest": self._seal}


def _claims(claims):
    if type(claims) is not list or len(claims) > 100:
        raise ValueError("claims must be a list of at most 100 entries")
    clean = []
    total = 0
    for claim in claims:
        if type(claim) is not dict or not {"text"} <= claim.keys() or claim.keys() - {"text", "cites", "quotes"}:
            raise ValueError("each claim requires text and optional cites/quotes")
        text, cites, quotes = claim["text"], claim.get("cites", []), claim.get("quotes", [])
        if (type(text) is not str or not text.strip() or len(text) > 4096
                or type(cites) is not list or len(cites) > 32
                or any(type(s) is not str or not re.fullmatch(r"snap-[0-9]{4}", s) for s in cites)
                or len(set(cites)) != len(cites)
                or type(quotes) is not list or len(quotes) > 32
                or any(type(q) is not str or not q.strip() or len(q) > 4096 for q in quotes)
                or len(set(quotes)) != len(quotes)):
            raise ValueError("invalid claim text, unique snapshot citations or unique nonblank quotes")
        try:
            total += len(text.encode()) + sum(len(q.encode()) for q in quotes)
        except UnicodeError as exc:
            raise ValueError("claim text and quotes require valid Unicode") from exc
        if total > 262144:
            raise ValueError("claim text/quotes exceed 256 KiB")
        clean.append({"text": text, "cites": list(cites), "quotes": list(quotes)})
    return clean
