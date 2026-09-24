from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import copy
import json
import threading
import time
import unittest
from unittest.mock import patch

import e07.core as core
from e07.core import (ResearchPolicy, ResearchGovernor, PolicyRefused, CaptureFailed,
                      IntegrityError, _hash)

URL = "https://docs.example.org/spec"


class Hardening(unittest.TestCase):
    def governor(self, transport=lambda url: b"alpha beta", quota=20):
        return ResearchGovernor(ResearchPolicy(["docs.example.org"], per_domain_quota=quota), transport)

    def test_domain_validation(self):
        for domains in ("x.org", [], [""], ["*.x.org"], ["localhost"], ["127.0.0.1"],
                        ["x.org:443"], ["x.org."], ["https://x.org"], ["é.org"], ["-x.org"]):
            with self.assertRaises(ValueError):
                ResearchPolicy(domains)

    def test_policy_exact_quota_types(self):
        for value in (True, 1.5, "2", 0, 1001):
            with self.assertRaises(ValueError):
                ResearchPolicy(["x.org"], per_domain_quota=value)

    def test_policy_immutable_and_detached(self):
        domains, paths = ["DOCS.EXAMPLE.ORG"], ["/secret"]
        p = ResearchPolicy(domains, paths)
        domains.append("evil.org")
        paths.clear()
        self.assertEqual(p.allowed, frozenset(["docs.example.org"]))
        self.assertEqual(p.deny_paths, ("/secret",))
        with self.assertRaises(FrozenInstanceError):
            p.quota = 0

    def test_explicit_empty_deny_list(self):
        g = ResearchGovernor(ResearchPolicy(["docs.example.org"], []), lambda url: b"x")
        self.assertIn("snapshot_id", g.fetch("https://docs.example.org/admin"))

    def test_invalid_path_rules(self):
        for rules in ("/admin", [""], ["admin"], ["/x/../admin"], ["/%zz"], [None]):
            with self.assertRaises(ValueError):
                ResearchPolicy(["docs.example.org"], rules)

    def test_url_bad_types_and_size(self):
        calls = []
        g = self.governor(lambda u: calls.append(u) or b"x")
        for value in (None, 2, b"https://docs.example.org", [], "https://docs.example.org/"+"x"*4096):
            with self.assertRaises(PolicyRefused):
                g.fetch(value)
        self.assertFalse(calls)
        self.assertEqual(g.access_report()["total_requests"], 5)

    def test_url_credentials_ports_fragments(self):
        g = self.governor()
        for value in ("https://user:secret@docs.example.org/spec", URL+"#x", URL+"#",
                      "https://docs.example.org:444/spec", "https://docs.example.org:/spec",
                      "https://docs.example.org:0443/spec", "https://docs.example.org./spec"):
            with self.assertRaises(PolicyRefused):
                g.fetch(value)
        self.assertNotIn("secret", json.dumps(g.ledger))

    def test_malformed_authority_and_controls(self):
        g = self.governor()
        for value in ("https://[broken/spec", "\n"+URL, URL+"\t", URL+" ", URL+"\x7f",
                      "https://docs.example.org\\@evil.org/spec", "https://döcs.example.org/spec"):
            with self.assertRaises(PolicyRefused):
                g.fetch(value)

    def test_canonical_url_passed_to_transport(self):
        calls = []
        g = self.governor(lambda u: calls.append(u) or b"x")
        g.fetch("HTTPS://DOCS.EXAMPLE.ORG:443/spec?q=1")
        self.assertEqual(calls, ["https://docs.example.org/spec?q=1"])
        self.assertEqual(g.snapshots["snap-0000"]["url"], calls[0])

    def test_host_prefix_and_suffix_refused(self):
        g = self.governor()
        for value in ("https://docs.example.org.evil.org/spec", "https://sub.docs.example.org/spec",
                      "https://evildocs.example.org/spec"):
            with self.assertRaises(PolicyRefused):
                g.fetch(value)

    def test_nested_percent_and_unicode_path_normalization(self):
        g = self.governor()
        for path in ("/%252561dmin", "/%2525252561dmin", "/%EF%BC%A1dmin",
                     "/%EF%BC%85%EF%BC%96%EF%BC%91dmin", "//ADMIN/config"):
            with self.assertRaises(PolicyRefused):
                g.fetch("https://docs.example.org"+path)

    def test_ambiguous_path_refused(self):
        g = self.governor()
        for path in ("/a/../admin", "/a/%2e%2e/admin", "/%5cadmin", "/ad;thing/min",
                     "/%zz", "/%ff", "/%00", "/%25literal", "/./public"):
            with self.assertRaises(PolicyRefused):
                g.fetch("https://docs.example.org"+path)

    def test_transport_failure_logged_and_charged(self):
        def failing(url):
            raise RuntimeError("secret failure details")
        g = self.governor(failing, quota=1)
        with self.assertRaises(CaptureFailed):
            g.fetch(URL)
        self.assertEqual(g.ledger[0]["status"], "TRANSPORT_ERROR")
        self.assertNotIn("secret", json.dumps(g.ledger))
        with self.assertRaises(PolicyRefused):
            g.fetch(URL)
        self.assertEqual(g.access_report()["per_domain_counts"], {"docs.example.org": 1})
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_wrong_transport_type_no_conversion(self):
        class Bad:
            def __str__(self):
                raise AssertionError("must not convert")
        g = self.governor(lambda u: Bad())
        with self.assertRaises(CaptureFailed):
            g.fetch(URL)
        self.assertEqual(g.ledger[0]["status"], "RESPONSE_REFUSED")
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_content_budget(self):
        g = self.governor(lambda u: b"x" * (core.MAX_CONTENT_BYTES + 1))
        with self.assertRaises(CaptureFailed):
            g.fetch(URL)
        self.assertFalse(g.snapshots)

    def test_total_store_budget(self):
        g = self.governor(lambda u: b"1234")
        with patch("e07.core.MAX_STORE_BYTES", 6):
            g.fetch(URL)
            with self.assertRaises(CaptureFailed):
                g.fetch(URL)
        self.assertEqual(len(g.snapshots), 1)
        self.assertEqual(g.access_report()["stored_bytes"], 4)

    def test_snapshot_capacity_before_transport(self):
        calls = []
        g = self.governor(lambda u: calls.append(u) or b"x")
        with patch("e07.core.MAX_SNAPSHOTS", 1):
            g.fetch(URL)
            with self.assertRaises(PolicyRefused):
                g.fetch(URL)
        self.assertEqual(len(calls), 1)

    def test_ledger_capacity_counts_without_growth(self):
        g = self.governor()
        with patch("e07.core.MAX_REQUESTS", 2):
            for _ in range(4):
                with self.assertRaises(PolicyRefused):
                    g.fetch("http://docs.example.org/x")
        report = g.access_report()
        self.assertEqual((report["total_requests"], report["recorded_requests"],
                          report["unrecorded_capacity_refusals"]), (4, 2, 2))
        self.assertEqual(len(g.ledger), 2)

    def test_concurrent_quota(self):
        calls = []
        def transport(url):
            time.sleep(0.005)
            calls.append(url)
            return b"x"
        g = self.governor(transport, quota=3)
        def fetch(_):
            try:
                return g.fetch(URL)["snapshot_id"]
            except PolicyRefused:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(fetch, range(10)))
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(set(v for v in results if v)), 3)
        self.assertEqual(g.access_report()["total_requests"], 10)
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_reentrant_transport_refused(self):
        g = None
        def transport(url):
            with self.assertRaises(PolicyRefused):
                g.fetch(url)
            return b"x"
        g = self.governor(transport)
        g.fetch(URL)
        self.assertEqual([e["status"] for e in g.ledger], ["CAPTURED", "REFUSED"])
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_transport_corruption_does_not_get_resealed(self):
        for throws in (False, True):
            g = None
            def transport(url):
                g._counts["docs.example.org"] = 0
                if throws:
                    raise RuntimeError()
                return b"x"
            g = self.governor(transport)
            with self.assertRaises(IntegrityError):
                g.fetch(URL)
            self.assertEqual(g.verify_snapshots()["verdict"], "FAIL")
            with self.assertRaises(IntegrityError):
                g.fetch(URL)

    def test_interrupted_transport_logged(self):
        def transport(url):
            raise KeyboardInterrupt()
        g = self.governor(transport)
        with self.assertRaises(KeyboardInterrupt):
            g.fetch(URL)
        self.assertEqual(g.ledger[0]["status"], "TRANSPORT_ERROR")
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_capture_timestamp_after_transport(self):
        with patch("e07.core.time.time", side_effect=[10.0, 12.0]):
            g = self.governor()
            g.fetch(URL)
        self.assertEqual(g.ledger[0]["requested_at"], 10)
        self.assertEqual(g.snapshots["snap-0000"]["captured_at"], 12)

    def test_public_snapshots_are_detached(self):
        g = self.governor()
        g.fetch(URL)
        snap = g.snapshots
        snap["snap-0000"]["url"] = "forged"
        snap.clear()
        self.assertEqual(len(g.snapshots), 1)
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_public_ledger_is_detached(self):
        g = self.governor()
        g.fetch(URL)
        entries = g.ledger
        entries[0]["allowed"] = False
        self.assertEqual(g.access_report()["allowed"], 1)

    def test_snapshot_metadata_tamper(self):
        for field, value in (("url", "https://evil.org"), ("captured_at", 1), ("snapshot_id", "snap-9999"),
                             ("content", b"changed"), ("content_digest", "sha256:bad")):
            g = self.governor()
            g.fetch(URL)
            g._snapshots["snap-0000"][field] = value
            self.assertEqual(g.verify_snapshots()["verdict"], "FAIL")
            with self.assertRaises(IntegrityError):
                g.bind_claims([{"text": "x", "cites": ["snap-0000"], "quotes": ["alpha"]}])

    def test_removed_snapshot_detected(self):
        g = self.governor()
        g.fetch(URL)
        g._snapshots.clear()
        self.assertEqual(g.verify_snapshots()["verdict"], "FAIL")

    def test_counts_ledger_policy_tamper(self):
        for field in ("count", "ledger", "policy"):
            g = self.governor()
            g.fetch(URL)
            if field == "count":
                g._counts.clear()
            elif field == "ledger":
                g._ledger.clear()
            else:
                object.__setattr__(g.policy, "quota", 1000)
            with self.assertRaises(IntegrityError):
                g.fetch(URL)

    def test_no_quote_is_not_semantic_support(self):
        g = self.governor()
        g.fetch(URL)
        report = g.bind_claims([{"text": "arbitrary claim", "cites": ["snap-0000"]}])
        self.assertEqual(report["claims"][0]["status"], "CITED_UNVERIFIED")
        self.assertEqual(report["evidence_bound"], 0)

    def test_every_quote_must_match(self):
        g = self.governor()
        g.fetch(URL)
        report = g.bind_claims([{"text": "x", "cites": ["snap-0000"], "quotes": ["alpha", "ghost"]}])
        self.assertEqual(report["claims"][0]["status"], "UNSUPPORTED")

    def test_every_citation_must_have_quote(self):
        pages = iter((b"alpha", b"unrelated"))
        g = self.governor(lambda u: next(pages))
        g.fetch(URL); g.fetch(URL)
        report = g.bind_claims([{"text": "x", "cites": ["snap-0000", "snap-0001"], "quotes": ["alpha"]}])
        self.assertEqual(report["claims"][0]["status"], "UNSUPPORTED")

    def test_quotes_can_bind_separate_sources(self):
        pages = iter((b"alpha", b"beta"))
        g = self.governor(lambda u: next(pages))
        g.fetch(URL); g.fetch(URL)
        report = g.bind_claims([{"text": "x", "cites": ["snap-0000", "snap-0001"], "quotes": ["alpha", "beta"]}])
        self.assertEqual(report["claims"][0]["status"], "EVIDENCE_BOUND")
        self.assertEqual(len(report["claims"][0]["bindings"]), 2)

    def test_utf8_byte_spans(self):
        content = "prefix é😀 suffix".encode()
        g = self.governor(lambda u: content)
        g.fetch(URL)
        report = g.bind_claims([{"text": "x", "cites": ["snap-0000"], "quotes": ["é😀"]}])
        match = report["claims"][0]["bindings"][0]
        self.assertEqual(content[match["byte_start"]:match["byte_end"]], "é😀".encode())

    def test_claim_validation(self):
        g = self.governor()
        for claims in (None, {}, [{"text": ""}], [{"text": "x", "extra": 1}],
                       [{"text": "x", "cites": ["snap-0000", "snap-0000"]}],
                       [{"text": "x", "quotes": [" "]}], [{"text": "x", "quotes": ["a", "a"]}],
                       [{"text": "\ud800"}], [{"text": "x", "cites": [[]]}]):
            with self.assertRaises(ValueError):
                g.bind_claims(claims)

    def test_claim_count_and_text_budget(self):
        g = self.governor()
        for claims in ([{"text": "x"}]*101, [{"text": "x"*4097}],
                       [{"text": "界"*4096}]*30):
            with self.assertRaises(ValueError):
                g.bind_claims(claims)

    def test_quote_scan_budget(self):
        g = self.governor(lambda u: b"alpha beta")
        g.fetch(URL)
        with patch("e07.core.MAX_QUOTE_SCAN_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "scan budget"):
                g.bind_claims([{"text": "x", "cites": ["snap-0000"], "quotes": ["alpha"]}])
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")

    def test_binding_count_budget(self):
        g = self.governor()
        g.fetch(URL)
        with patch("e07.core.MAX_BINDINGS", 1):
            with self.assertRaisesRegex(ValueError, "bindings"):
                g.bind_claims([{"text": "x", "cites": ["snap-0000"], "quotes": ["alpha", "beta"]}])

    def test_report_size_budget(self):
        g = self.governor()
        with patch("e07.core.MAX_REPORT_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "JSON budget"):
                g.bind_claims([{"text": "x"}])

    def test_report_digest_and_detachment(self):
        g = self.governor()
        g.fetch(URL)
        claims = [{"text": "x", "cites": ["snap-0000"], "quotes": ["alpha"]}]
        report = g.bind_claims(claims)
        digest = report.pop("report_digest")
        self.assertEqual(digest, _hash(report))
        claims[0]["quotes"][0] = "forged"
        self.assertEqual(report["claims"][0]["quotes"], ["alpha"])
        report["claims"][0]["evidence"][0]["url"] = "changed"
        self.assertEqual(g.snapshots["snap-0000"]["url"], URL)

    def test_empty_capture_and_report(self):
        g = self.governor(lambda u: b"")
        self.assertEqual(g.fetch(URL)["bytes"], 0)
        self.assertEqual(g.bind_claims([])["claims"], [])

    def test_policy_copy_isolated_from_original(self):
        policy = ResearchPolicy(["docs.example.org"])
        g = ResearchGovernor(policy, lambda u: b"x")
        object.__setattr__(policy, "quota", 0)
        self.assertIn("snapshot_id", g.fetch(URL))
