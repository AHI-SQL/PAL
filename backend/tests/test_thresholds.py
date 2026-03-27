from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "backend" / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pal_backend.thresholds import PUBLIC_THRESHOLD_FILES, ThresholdRepository


class ThresholdRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        threshold_dir = ROOT / "resources" / "thresholds"
        cls.repo = ThresholdRepository(threshold_dir)

    def test_list_threshold_files(self) -> None:
        items = self.repo.list_threshold_files()
        self.assertTrue(items)
        self.assertEqual({item.file_name for item in items}, set(PUBLIC_THRESHOLD_FILES))

    def test_get_threshold_file(self) -> None:
        detail = self.repo.get_threshold_file("QuickSystemOverview.xml")
        self.assertEqual(detail.display_name, "Quick System Overview")
        self.assertGreater(len(detail.analyses), 0)
        self.assertGreater(len(detail.questions), 0)

    def test_inheritance_is_resolved(self) -> None:
        detail = self.repo.get_threshold_file("SystemOverview.xml")
        self.assertGreater(len(detail.analyses), 0)

    def test_non_public_threshold_file_is_hidden(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.repo.get_threshold_file("Exchange2010.xml")


if __name__ == "__main__":
    unittest.main()
