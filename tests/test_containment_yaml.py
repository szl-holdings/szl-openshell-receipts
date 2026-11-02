"""Policy YAML must preserve literal paths instead of YAML syntax."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "containment_yaml", ROOT / "src/szl_openshell_receipts/containment.py"
)
c = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(c)


class PolicyYamlTests(unittest.TestCase):
    def test_path_syntax_is_quoted_in_both_permission_lists(self):
        cases = [
            ("/workspace/allowed #literal", '"/workspace/allowed #literal"'),
            ("/workspace/part: child", '"/workspace/part: child"'),
            ('/workspace/"quoted"\\leaf', '"/workspace/\\"quoted\\"\\\\leaf"'),
            ("/workspace/leaf\n  read_write:\n    - /", '"/workspace/leaf\\n  read_write:\\n    - /"'),
            ("/workspace/\0\t\x85\u2028\u2029", '"/workspace/\\u0000\\t\\u0085\\u2028\\u2029"'),
            ("/workspace/\u00e9\U0001f600", '"/workspace/\\u00e9\\U0001f600"'),
            (r"C:\workspace\file", '"C:\\\\workspace\\\\file"'),
        ]
        for access in ("read_only", "read_write"):
            for path, scalar in cases:
                with self.subTest(access=access, path=path):
                    text = c.to_yaml({"version": 1, "filesystem_policy": {access: [path]}})
                    self.assertEqual(
                        text,
                        "version: 1\nfilesystem_policy:\n  " + access + ":\n    - " + scalar + "\n",
                    )

    def test_repaired_path_remains_literal_in_serialized_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            allowed = Path(folder) / "allowed #literal"
            allowed.mkdir()
            boundary = {"version": 1, "filesystem_policy": {"read_write": [str(allowed)]}}
            repaired = c.repair(boundary, boundary)
            serialized = c.to_yaml(repaired)
            # JSON double-quoted scalars are also YAML double-quoted scalars.
            scalar = serialized.split("    - ", 1)[1].strip()
            restored = json.loads(scalar)
            self.assertEqual(restored, str(allowed))
            self.assertEqual(c.check(
                {"version": 1, "filesystem_policy": {"read_write": [restored]}}, boundary
            )["result"], "within_boundary")

    def test_empty_policy_remains_empty(self):
        self.assertEqual(c.to_yaml({}), "version: 1\nfilesystem_policy: {}\n")


if __name__ == "__main__":
    unittest.main()
