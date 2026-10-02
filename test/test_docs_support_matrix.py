from pathlib import Path
from runpy import run_path
from unittest import TestCase


class DocsSupportMatrixTest(TestCase):
    def test_armv6_has_no_extended_edition(self):
        macros = run_path(str(Path(__file__).resolve().parents[1] / 'docs/.theme/marcos/main.py'))
        self.assertEqual(
            [macros['EditionKind'].generic],
            list(macros['support_matrix'].entries[macros['Os'].linux][macros['Arch'].armv6]),
        )
