import unittest

from e07.core import PolicyRefused, ResearchGovernor, ResearchPolicy

PAGES = {
    "https://docs.example.org/spec": b"The protocol uses port 8443 by default.",
    "https://docs.example.org/faq": b"Rate limits reset every 60 seconds.",
    "https://blog.example.org/post": b"An opinion piece about protocols.",
}


def offline_transport(url):
    return PAGES[url]


def make(quota=20):
    policy = ResearchPolicy(["docs.example.org", "blog.example.org"],
                            per_domain_quota=quota)
    return ResearchGovernor(policy, offline_transport)


class Policy(unittest.TestCase):
    def test_allowlist_required_and_quota_bounds(self):
        with self.assertRaises(ValueError):
            ResearchPolicy([])
        with self.assertRaises(ValueError):
            ResearchPolicy(["x.org"], per_domain_quota=0)

    def test_https_only(self):
        g = make()
        with self.assertRaises(PolicyRefused):
            g.fetch("http://docs.example.org/spec")

    def test_domain_allowlist_exact(self):
        g = make()
        for bad in ("https://evil.example.com/x",
                    "https://sub.docs.example.org/x"):
            with self.assertRaises(PolicyRefused, msg=bad):
                g.fetch(bad)

    def test_denied_paths(self):
        g = make()
        with self.assertRaises(PolicyRefused):
            g.fetch("https://docs.example.org/admin/config")

    def test_refusals_recorded_in_ledger(self):
        g = make()
        try:
            g.fetch("https://evil.example.com/x")
        except PolicyRefused:
            pass
        rep = g.access_report()
        self.assertEqual(rep["allowed"], 0)
        self.assertEqual(len(rep["refused"]), 1)
        self.assertIn("allowlist", rep["refused"][0]["reason"])

    def test_quota_exhaustion(self):
        g = make(quota=2)
        g.fetch("https://docs.example.org/spec")
        g.fetch("https://docs.example.org/faq")
        with self.assertRaises(PolicyRefused) as ctx:
            g.fetch("https://docs.example.org/spec")
        self.assertIn("quota", str(ctx.exception))


class Snapshots(unittest.TestCase):
    def test_capture_with_provenance_and_no_overwrite(self):
        g = make()
        r1 = g.fetch("https://docs.example.org/spec")
        r2 = g.fetch("https://docs.example.org/spec")   # new snapshot
        self.assertNotEqual(r1["snapshot_id"], r2["snapshot_id"])
        self.assertEqual(r1["content_digest"], r2["content_digest"])
        self.assertEqual(len(g.snapshots), 2)
        snap = g.snapshots[r1["snapshot_id"]]
        self.assertEqual(snap["url"], "https://docs.example.org/spec")

    def test_integrity_verification(self):
        g = make()
        r = g.fetch("https://docs.example.org/spec")
        self.assertEqual(g.verify_snapshots()["verdict"], "PASS")
        g._snapshots[r["snapshot_id"]]["content"] = b"tampered"
        rep = g.verify_snapshots()
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertIn(r["snapshot_id"], rep["tampered"])


class Claims(unittest.TestCase):
    def setUp(self):
        self.g = make()
        self.spec = self.g.fetch("https://docs.example.org/spec")["snapshot_id"]
        self.faq = self.g.fetch("https://docs.example.org/faq")["snapshot_id"]

    def test_supported_claim_with_quote(self):
        rep = self.g.bind_claims([{"text": "default port is 8443",
                                   "cites": [self.spec],
                                   "quotes": ["port 8443"]}])
        self.assertEqual(rep["claims"][0]["status"], "EVIDENCE_BOUND")
        ev = rep["claims"][0]["evidence"][0]
        self.assertEqual(ev["snapshot_id"], self.spec)
        self.assertTrue(ev["content_digest"].startswith("sha256:"))

    def test_unbacked_claims_flagged(self):
        rep = self.g.bind_claims([
            {"text": "no citations at all"},
            {"text": "cites a ghost", "cites": ["snap-9999"]},
            {"text": "quote not in source", "cites": [self.faq],
             "quotes": ["port 8443"]},
        ])
        statuses = [c["status"] for c in rep["claims"]]
        self.assertEqual(statuses, ["UNSUPPORTED"] * 3)
        reasons = " | ".join(c["reason"] for c in rep["claims"])
        self.assertIn("no citations", reasons)
        self.assertIn("not in store", reasons)
        self.assertIn("not present", reasons)
        self.assertEqual(rep["unsupported"], 3)

    def test_mixed_report_counts(self):
        rep = self.g.bind_claims([
            {"text": "limits reset each minute", "cites": [self.faq],
             "quotes": ["reset every 60 seconds"]},
            {"text": "made up", "cites": []},
        ])
        self.assertEqual((rep["evidence_bound"], rep["unsupported"]), (1, 1))


class Injection(unittest.TestCase):
    def test_no_builtin_network_client(self):
        import e07.core as m
        from pathlib import Path
        src = Path(m.__file__).read_text(encoding="utf-8")
        imports = [l for l in src.splitlines()
                   if l.startswith(("import ", "from "))]
        joined = " ".join(imports)
        for bad in ("urllib.request", "http.client", "socket", "requests",
                    "aiohttp", "httpx"):
            self.assertNotIn(bad, joined)

    def test_transport_never_called_on_refusal(self):
        calls = []

        def spy(url):
            calls.append(url)
            return b"x"
        g = ResearchGovernor(ResearchPolicy(["ok.org"]), spy)
        try:
            g.fetch("https://bad.org/x")
        except PolicyRefused:
            pass
        self.assertEqual(calls, [])
        g.fetch("https://ok.org/page")
        self.assertEqual(calls, ["https://ok.org/page"])


if __name__ == "__main__":
    unittest.main()


class Hardening011(unittest.TestCase):
    """Regression tests for the 0.1.1-partial fixes (audit A024)."""

    def setUp(self):
        self.g = make()

    def test_deny_path_case_and_percent_encoding(self):        # A024-F1
        for bad in ("https://docs.example.org/Admin/config",
                    "https://docs.example.org/ADMIN",
                    "https://docs.example.org/%61dmin/config",
                    "https://docs.example.org/%2561dmin/config"):
            with self.assertRaises(PolicyRefused, msg=bad):
                self.g.fetch(bad)
        # plain allowed path still fetches
        self.assertIn("snapshot_id",
                      self.g.fetch("https://docs.example.org/spec"))

    def test_empty_quote_rejected(self):                        # A024-F2
        snap = self.g.fetch("https://docs.example.org/spec")["snapshot_id"]
        with self.assertRaises(ValueError):
            self.g.bind_claims([{"text": "fabricated", "cites": [snap],
                                 "quotes": [""]}])
        # a real quote still supports
        rep = self.g.bind_claims([{"text": "ok", "cites": [snap],
                                   "quotes": ["port 8443"]}])
        self.assertEqual(rep["claims"][0]["status"], "EVIDENCE_BOUND")

    def test_malformed_claims_raise_valueerror(self):           # A024-F3
        snap = self.g.fetch("https://docs.example.org/spec")["snapshot_id"]
        for bad in ([{"cites": [snap]}],                # missing text
                    [{"text": 7, "cites": [snap]}],     # non-string text
                    [{"text": "x", "cites": "snap-0000"}],  # cites not list
                    [{"text": "x", "cites": [snap], "quotes": [42]}]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.g.bind_claims(bad)

    def test_access_report_isolated_from_ledger(self):          # A024-F4
        try:
            self.g.fetch("http://docs.example.org/x")
        except PolicyRefused:
            pass
        rep = self.g.access_report()
        rep["refused"][0]["reason"] = "FORGED"
        self.assertNotEqual(
            [e["reason"] for e in self.g.ledger if not e["allowed"]][0],
            "FORGED")

    def test_version_constant(self):
        import e07.core as m
        self.assertEqual(m.__version__, "0.1.2a1")
