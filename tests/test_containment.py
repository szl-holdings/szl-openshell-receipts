import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("szl_containment", ROOT / "src/szl_openshell_receipts/containment.py")
c = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c)


def pol(ro=(), rw=()):
    fs = {}
    if ro:
        fs["read_only"] = list(ro)
    if rw:
        fs["read_write"] = list(rw)
    return {"version": 1, "filesystem_policy": fs}


class Semantics(unittest.TestCase):
    def test_probe_cases(self):
        b = pol(["/usr", "/etc"])
        self.assertEqual(c.check(pol(["/usr"]), b)["result"], "within_boundary")
        r = c.check(pol(["/usr"], ["/tmp"]), b)
        self.assertEqual(r["violations"], [{"domain": "filesystem", "access": "write", "path": "/tmp"}])

    def test_prefix_is_component_wise(self):
        self.assertTrue(c.covers("/usr", "/usr/lib"))
        self.assertFalse(c.covers("/usr", "/usrx"))
        self.assertTrue(c.covers("/", "/anything"))
        self.assertTrue(c.covers("/usr/", "/usr/lib"))

    def test_repair_is_contained(self):
        b = pol(["/usr"], ["/tmp"])
        fixed = c.repair(pol(["/usr/lib", "/home"], ["/tmp/x", "/usr/share", "/var"]), b)
        self.assertEqual(c.check(fixed, b)["result"], "within_boundary")
        self.assertIn("/usr/share", fixed["filesystem_policy"]["read_only"])
        self.assertNotIn("/home", fixed["filesystem_policy"]["read_only"])


class Parity(unittest.TestCase):
    def test_recorded_parity_fixture(self):
        f = ROOT / "tests" / "fixtures" / "prover_parity.jsonl"
        rows = [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()]
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(c.check(row["candidate"], row["boundary"])["result"], row["witness_result"], row["id"])


if __name__ == "__main__":
    unittest.main()
