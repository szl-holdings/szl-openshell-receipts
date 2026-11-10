import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from szl_openshell_receipts import (ReceiptChain, approval_event, bundle, classify, delta, gate,
                                    parse_log, validate_ledger, verify_chain)


def build():
    chain = ReceiptChain("run-1", "a" * 64, "b" * 40)
    chain.append({"class_name": "network_activity", "disposition": "denied"}, "2026-01-01T00:00:00+00:00")
    chain.append({"class_name": "policy_proposal", "status": "pending review"}, "2026-01-01T00:00:01+00:00")
    chain.append({"class_name": "network_activity", "disposition": "allowed"}, "2026-01-01T00:00:02+00:00")
    return chain


class ChainTests(unittest.TestCase):
    def test_verifies(self):
        self.assertTrue(verify_chain(build().receipts)[0])

    def test_tamper_detected(self):
        r = build().receipts
        r[1]["decision"] = "ALLOW"
        self.assertFalse(verify_chain(r)[0])

    def test_reorder_detected(self):
        r = build().receipts
        r[0], r[1] = r[1], r[0]
        self.assertFalse(verify_chain(r)[0])

    def test_deterministic(self):
        self.assertEqual([x["receipt_digest"] for x in build().receipts],
                         [x["receipt_digest"] for x in build().receipts])

    def test_keyword_classify(self):
        self.assertEqual(classify({"action": "disallow"}), "DENY")
        self.assertEqual(classify({"status": "pending review"}), "REVIEW_REQUIRED")
        self.assertEqual(classify({"disposition": "allowed"}), "ALLOW")
        self.assertEqual(classify({"foo": "bar"}), "OBSERVED")

    def test_stress_5000(self):
        chain = ReceiptChain("stress", "c" * 64, "d" * 40)
        start = time.time()
        for i in range(5000):
            chain.append({"class_name": "file_activity", "status": "allowed", "i": i}, "2026-01-01T00:00:00+00:00")
        self.assertTrue(verify_chain(chain.receipts)[0])
        self.assertLess(time.time() - start, 30)


class LogTests(unittest.TestCase):
    def test_sample_log(self):
        events, skipped = parse_log((ROOT / "examples" / "openshell.sample.log").read_text(encoding="utf-8"))
        self.assertEqual(len(events), 5)
        self.assertEqual(skipped, 1)
        chain = ReceiptChain("log", "e" * 64, "f" * 40)
        for e in events:
            chain.append(e, "2026-01-01T00:00:00+00:00")
        self.assertEqual([r["decision"] for r in chain.receipts],
                         ["DENY", "REVIEW_REQUIRED", "ALLOW", "OBSERVED", "ALLOW"])
        self.assertTrue(all(r["evidence_basis"] == "OPENSHELL_LOG_TOKEN" for r in chain.receipts))
        self.assertTrue(all("raw" not in json.dumps(r) for r in chain.receipts))

    def test_auto_approval_anomaly_flag(self):
        events, _ = parse_log("x CONFIG:APPROVED chunk_id=c9 auto=true prover_delta=capability_expansion")
        chain = ReceiptChain("anomaly", "e" * 64, "f" * 40)
        r = chain.append(events[0], "2026-01-01T00:00:00+00:00")
        self.assertIn("AUTO_APPROVAL_WITH_NONEMPTY_DELTA", r["flags"])


class ReachTests(unittest.TestCase):
    def load(self, name):
        return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))

    def test_categories(self):
        result = delta(self.load("policy.before.json"), self.load("policy.after.json"))
        cats = {f["category"] for f in result["findings"]}
        self.assertEqual(cats, {"capability_expansion", "link_local_reach",
                                "l7_bypass_credentialed", "credential_reach_expansion"})
        self.assertGreater(result["expansion_ratio"], 0)

    def test_gate_requires_second_witness(self):
        same = self.load("policy.before.json")
        self.assertEqual(gate(delta(same, same)["findings"])["decision"], "REVIEW_REQUIRED")
        self.assertEqual(gate(delta(same, same)["findings"], [])["decision"], "ALLOW_ELIGIBLE")

    def test_disagreement(self):
        same = self.load("policy.before.json")
        g = gate(delta(same, same)["findings"], ["capability_expansion"])
        self.assertEqual(g["decision"], "REVIEW_REQUIRED")
        self.assertIn("WITNESS_DISAGREEMENT", g["reasons"])

    def test_link_local_literals_and_metadata_aliases_require_review(self):
        hosts = (
            "169.254.0.0", "169.254.255.255", "fe80::", "fe90::1",
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "FE90::1",
            "fe90::1%eth0", "[fe90::1]", "[fe90::1%eth0]",
            "::ffff:169.254.169.254", "::ffff:a9fe:a9fe",
            "[::ffff:169.254.169.254]", "metadata.google.internal.",
            "METADATA.GOOGLE.INTERNAL.", "metadata.",
        )
        for host in hosts:
            with self.subTest(host=host):
                new = {"rules": [{"binary": "curl", "host": host, "port": 80,
                                  "methods": ["GET"], "credentialed": False}]}
                result = delta({"rules": []}, new)
                self.assertEqual([f["category"] for f in result["findings"]],
                                 ["link_local_reach"])
                # An empty external prover result must not clear this finding.
                decision = gate(result["findings"], [])
                self.assertEqual(decision["decision"], "REVIEW_REQUIRED")
                self.assertIn("WITNESS_DISAGREEMENT", decision["reasons"])

    def test_link_local_detection_keeps_unrelated_hosts_out(self):
        for host in ("169.253.255.255", "169.255.0.0", "fe7f::1", "fec0::1",
                     "2001:db8::1", "::ffff:192.0.2.1", "example.com",
                     "metadata.google.internal.example.com"):
            with self.subTest(host=host):
                new = {"rules": [{"binary": "curl", "host": host, "port": 80,
                                  "methods": ["GET"], "credentialed": False}]}
                self.assertEqual(delta({"rules": []}, new)["findings"], [])

    def test_legacy_ipv4_link_local_forms_require_review(self):
        hosts = (
            "2852039166", "0xa9fea9fe", "0XA9FEA9FE",
            "0251.0376.0251.0376", "169.16689662", "0xa9.0xfea9fe",
            "169.254.43518", "0xa9.0376.0xa9fe", "169.0xfe.0251.254",
            "0xa9fe0000", "0xa9feffff", "0xa9fea9fe.",
            "0x0000a9fea9fe", "000000251.0000376.0000251.0000376",
        )
        for host in hosts:
            with self.subTest(host=host):
                new = {"rules": [{"binary": "curl", "host": host, "port": 80}]}
                result = delta({"rules": []}, new)
                self.assertEqual([f["category"] for f in result["findings"]],
                                 ["link_local_reach"])
                self.assertEqual(result["added"][0]["host"], host.lower())
                self.assertEqual(gate(result["findings"], [])["decision"],
                                 "REVIEW_REQUIRED")
                self.assertEqual(delta(new, new)["findings"], [])

    def test_legacy_ipv4_parser_keeps_invalid_and_unrelated_hosts_out(self):
        hosts = (
            "0xa9fdffff", "0xa9ff0000", "0xc0000201", "3221225985",
            "192.513", "0300.0.02.01", "0", "0xffffffff",
            "0x1a9fea9fe", "4294967296", "256.0.0.1", "169.16777216",
            "0xa9.0xfe.65536", "0xa9.0xfe.169.256",
            "0xa9fea9fe.example.com",
            "0x", "0xa9..0xfe", "0xa9.0xfe.0xa9.0xfe.1",
            "+2852039166", "-2852039166", "0xa9fea9fejunk", "0251.0386.0.1",
            "２８５２０３９１６６", "0xa9fea9fe ", "0xa9fea9fe..",
        )
        for host in hosts:
            with self.subTest(host=host):
                new = {"rules": [{"binary": "curl", "host": host, "port": 80}]}
                self.assertEqual(delta({"rules": []}, new)["findings"], [])

    def test_legacy_ipv4_does_not_remove_conservative_prefix_findings(self):
        for host in ("169.254.example.com", "169.254.65536", "fe80:invalid"):
            with self.subTest(host=host):
                new = {"rules": [{"binary": "curl", "host": host, "port": 80}]}
                self.assertEqual([f["category"] for f in delta({"rules": []}, new)["findings"]],
                                 ["link_local_reach"])

    def test_legacy_ipv4_long_numbers_do_not_depend_on_int_string_limit(self):
        for host, expected in (("0x" + "0" * 5000 + "a9fea9fe", ["link_local_reach"]),
                               ("0x" + "f" * 5000, [])):
            new = {"rules": [{"binary": "curl", "host": host, "port": 80}]}
            self.assertEqual([f["category"] for f in delta({"rules": []}, new)["findings"]],
                             expected)

    def test_existing_restricted_reach_is_not_a_new_expansion(self):
        policy = {"rules": [{"binary": "curl", "host": "fe90::1", "port": 80,
                             "methods": ["GET"], "credentialed": False}]}
        self.assertEqual(delta(policy, policy)["findings"], [])

    def test_wildcard_covers(self):
        old = {"rules": [{"binary": "/usr/bin/gh", "host": "api.github.com", "port": 443, "methods": ["*"], "credentialed": True}]}
        new = {"rules": [{"binary": "/usr/bin/gh", "host": "api.github.com", "port": 443, "methods": ["*", "PUT"], "credentialed": True}]}
        self.assertEqual(delta(old, new)["added"], [])


class ApprovalControlsMultimodalTests(unittest.TestCase):
    def test_approval_binds_token_digest_only(self):
        e = approval_event("c1", "h" * 64, "secret-token", "stephenlutar2-hash", "approve", "2026-12-31T00:00:00Z")
        self.assertNotIn("secret-token", json.dumps(e))
        self.assertEqual(len(e["review_token_digest"]), 64)
        with self.assertRaises(ValueError):
            approval_event("c1", "h", "", "x", "approve", "t")

    def test_controls_ledger(self):
        ok, problems, info = validate_ledger(json.loads((ROOT / "governance" / "controls.json").read_text(encoding="utf-8")))
        self.assertTrue(ok, problems)
        bad = {"controls": [{"id": "X", "requirement": "r", "control": "c", "owner": "o", "evidence": "e", "status": "MEASURED"}]}
        self.assertFalse(validate_ledger(bad)[0])

    def test_combination_changes_digest(self):
        a = bundle({"text": b"alpha", "image": b"beta"})
        b = bundle({"text": b"beta", "image": b"alpha"})
        self.assertEqual(sorted(a["channels"].values()), sorted(b["channels"].values()))
        self.assertNotEqual(a["combined_digest"], b["combined_digest"])


if __name__ == "__main__":
    unittest.main()
