import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from szl_openshell_receipts.cli import main


AMBIGUOUS_JSON = (
    '{"outer":{"mode":"deny","mode":"allow"}}',
    '{"value":NaN}',
    '{"value":Infinity}',
    '{"value":-Infinity}',
    '{"value":1e999}',
)


class StrictJsonAdmission(unittest.TestCase):
    def _call(self, folder, *args):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return main(["--root", folder, *args])

    def test_ingest_rejects_ambiguous_events_before_output(self):
        for document in AMBIGUOUS_JSON:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "events.jsonl").write_text(document + "\n")
                (root / "policy.json").write_text("{}")
                (root / "out.jsonl").write_text("sentinel\n")
                code = self._call(
                    folder,
                    "ingest",
                    "events.jsonl",
                    "--policy",
                    "policy.json",
                    "--commit",
                    "a" * 40,
                    "--out",
                    "out.jsonl",
                )
                self.assertEqual(code, 2)
                self.assertEqual((root / "out.jsonl").read_text(), "sentinel\n")

    def test_ingest_accepts_finite_decimal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "events.jsonl").write_text('\n   \n{"value":1.5}\n\n')
            (root / "policy.json").write_text("{}")
            self.assertEqual(
                self._call(
                    folder,
                    "ingest",
                    "events.jsonl",
                    "--policy",
                    "policy.json",
                    "--commit",
                    "a" * 40,
                    "--out",
                    "out.jsonl",
                ),
                0,
            )
            self.assertEqual(self._call(folder, "verify", "out.jsonl"), 0)

    def test_verify_rejects_ambiguous_receipts(self):
        for document in AMBIGUOUS_JSON:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as folder:
                Path(folder, "receipts.jsonl").write_text(document + "\n")
                self.assertEqual(self._call(folder, "verify", "receipts.jsonl"), 2)

    def test_delta_rejects_ambiguous_old_and_new_policies(self):
        for bad_name in ("old.json", "new.json"):
            for document in AMBIGUOUS_JSON:
                with self.subTest(bad_name=bad_name, document=document), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    (root / "old.json").write_text("{}")
                    (root / "new.json").write_text("{}")
                    (root / bad_name).write_text(document)
                    self.assertEqual(self._call(folder, "delta", "old.json", "new.json"), 2)

    def test_controls_rejects_ambiguous_ledger(self):
        for document in AMBIGUOUS_JSON:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as folder:
                Path(folder, "controls.json").write_text(document)
                self.assertEqual(self._call(folder, "controls", "controls.json"), 2)


if __name__ == "__main__":
    unittest.main()
