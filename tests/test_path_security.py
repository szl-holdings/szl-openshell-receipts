import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from szl_openshell_receipts import containment
from szl_openshell_receipts.cli import main


class PathSecurity(unittest.TestCase):
    def test_traversal_and_invalid_paths_are_not_covered(self):
        for path in ("/usr/../etc", "/usr//../etc", "/usr/./../etc", "/usr/\0x", "usr/lib", "", 3):
            with self.subTest(path=path):
                self.assertFalse(containment.covers("/usr", path))

    def test_duplicate_separators_are_component_normalized(self):
        self.assertTrue(containment.covers("/usr//", "/usr//lib/./x"))
        self.assertFalse(containment.covers("/usr", "/usr-extra/x"))

    def test_symlink_escape_is_not_covered(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "workspace"; root.mkdir()
            outside = Path(folder) / "outside"; outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)
            self.assertFalse(containment.covers(str(root), str(root / "escape" / "new.jsonl")))

    def test_cli_rejects_outside_output_before_touching_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "workspace"; root.mkdir()
            sentinel = Path(folder) / "outside.jsonl"; sentinel.write_text("sentinel")
            (root / "events.jsonl").write_text('{}\n')
            (root / "policy.json").write_text('{}')
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                code = main(["--root", str(root), "ingest", "events.jsonl", "--policy", "policy.json", "--commit", "a" * 40, "--out", "../outside.jsonl"])
            self.assertEqual(code, 2)
            self.assertEqual(sentinel.read_text(), "sentinel")

    def test_cli_rejects_symlinked_input_and_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "workspace"; root.mkdir()
            outside = Path(folder) / "outside"; outside.mkdir()
            sentinel = outside / "sentinel"; sentinel.write_text("sentinel")
            (root / "escape").symlink_to(outside, target_is_directory=True)
            (root / "events.jsonl").write_text('{}\n')
            (root / "policy.json").write_text('{}')
            for args in (["verify", "escape/sentinel"], ["ingest", "events.jsonl", "--policy", "policy.json", "--commit", "a" * 40, "--out", "escape/sentinel"]):
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["--root", str(root), *args]), 2)
            self.assertEqual(sentinel.read_text(), "sentinel")

    def test_cli_valid_workspace_ingest_and_verify(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "events.jsonl").write_text('{"status":"allowed"}\n')
            (root / "policy.json").write_text('{}')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--root", folder, "ingest", "events.jsonl", "--policy", "policy.json", "--commit", "a" * 40, "--out", "out.jsonl"]), 0)
                self.assertEqual(main(["--root", folder, "verify", "out.jsonl"]), 0)


    def test_symlink_loop_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "loop").symlink_to("loop")
            self.assertFalse(containment.covers(folder, str(root / "loop")))

    def test_nul_and_symlink_replacement_after_preflight_are_refused(self):
        from szl_openshell_receipts.workspace import Workspace
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "workspace"; root.mkdir()
            outside = Path(folder) / "outside"; outside.write_text("sentinel")
            target = root / "input"; target.write_text("safe")
            with Workspace(root) as files:
                for value in ("input\0tail", "../outside", str(outside)):
                    with self.assertRaises(ValueError): files.validate(value)
                files.validate("input")
                target.unlink(); target.symlink_to(outside)
                with self.assertRaises(OSError): files.read_text("input")
                with self.assertRaises(ValueError): files.write_text("input", "replacement")
            self.assertEqual(outside.read_text(), "sentinel")


if __name__ == "__main__":
    unittest.main()
