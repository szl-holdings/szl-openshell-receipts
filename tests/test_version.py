"""Version agreement in the source-only CI lane (no installed distribution)."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import szl_openshell_receipts


@unittest.skipIf(sys.version_info < (3, 11), "source metadata parser requires stdlib tomllib")
class VersionTests(unittest.TestCase):
    def test_runtime_matches_project_metadata(self):
        import tomllib
        with (ROOT / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source)["project"]
        self.assertEqual(szl_openshell_receipts.__version__, project["version"])
