"""Integrity checks for reference/observation_checker inside the required test job.

The reference stays outside the installable package. The observation-checker CI job
reproduces it in full; these checks keep its hash-bound bytes and example report honest.
"""
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "reference" / "observation_checker"
# Primary identities from the bundle's completion_receipt.md.
CHECKER_SHA256 = "888e1ffc3b1ebdfe0239a64052e17d69beb691b93d1bfdd00c3f127f60888fb6"
FIXTURES_SHA256 = "d6f1578a043c8976729d3a9d7e7ea632ab8386490d3b258544a3003eb25bfb11"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ObservationReferenceTests(unittest.TestCase):
    def test_sha256sums_bind_every_file(self):
        listed = {}
        for row in (REF / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            expected, name = row.split(maxsplit=1)
            listed[name.lstrip("*")] = expected
        present = {p.relative_to(REF).as_posix() for p in REF.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
        self.assertEqual(present - {"SHA256SUMS"}, set(listed))
        for name, expected in sorted(listed.items()):
            self.assertEqual(sha256(REF / name), expected, name)

    def test_primary_identities_match_completion_receipt(self):
        self.assertEqual(sha256(REF / "observation_checker.py"), CHECKER_SHA256)
        self.assertEqual(sha256(REF / "fixtures.json"), FIXTURES_SHA256)

    def test_example_cli_report_reproduces(self):
        run = subprocess.run(
            [sys.executable, "-B", str(REF / "observation_checker.py"), str(REF / "example_bundle.json"), str(REF / "example_policy.json")],
            capture_output=True, check=True, timeout=30, cwd=REF,
        )
        # Text-mode stdout writes CRLF on Windows; the committed report is LF.
        self.assertEqual(run.stdout.replace(b"\r\n", b"\n"), (REF / "example_report.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
