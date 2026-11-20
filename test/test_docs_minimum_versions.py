import re
from pathlib import Path
from runpy import run_path
from unittest import TestCase
from xml.etree import ElementTree

import markdown
from material.extensions.emoji import to_svg, twemoji


ROOT = Path(__file__).resolve().parents[1]


class MacroEnvironment:
    def __init__(self):
        self.macros = {}

    def macro(self, function):
        self.macros[function.__name__] = function
        return function


class DocsMinimumVersionsTest(TestCase):
    def setUp(self):
        environment = MacroEnvironment()
        module = run_path(str(ROOT / 'docs/.theme/marcos/main.py'))
        module['define_env'](environment)
        self.minimum_version = environment.macros['minimum_version']

    def render(self, *cells):
        source = '| Minimum version |\n| --- |\n' + '\n'.join(f'| {cell} |' for cell in cells)
        rendered = markdown.markdown(
            source,
            extensions=['tables', 'attr_list', 'pymdownx.emoji'],
            extension_configs={'pymdownx.emoji': {'emoji_index': twemoji, 'emoji_generator': to_svg}},
        )
        return ElementTree.fromstring(rendered)

    def test_every_version_has_an_asterisk_with_hover_and_click_notes(self):
        table = self.render(
            self.minimum_version('8.15.0', 'curl 8.18.0 on Linux.'),
            self.minimum_version('8.16.0', 'curl 8.22.0 on Windows.'),
        )
        rows = table.findall('./tbody/tr')
        self.assertEqual(2, len(rows))
        identifiers = []
        for row, version, tested in zip(rows, ['8.15.0', '8.16.0'], ['8.18.0', '8.22.0']):
            cell = row.find('td')
            self.assertEqual(version, cell.find('code').text)
            button = cell.find('button')
            note = cell.find('span')
            self.assertEqual('button', button.attrib['type'])
            self.assertEqual(note.attrib['id'], button.attrib['popovertarget'])
            self.assertEqual(note.attrib['id'], button.attrib['aria-describedby'])
            self.assertEqual('auto', note.attrib['popover'])
            self.assertEqual('note', note.attrib['role'])
            self.assertIn(version, button.attrib['aria-label'])
            self.assertIn('Expected minimum version', button.attrib['title'])
            self.assertIn('not a verified lower bound.', button.attrib['title'])
            self.assertIn(tested, button.attrib['title'])
            self.assertEqual(button.attrib['title'], note.text)
            self.assertIsNotNone(button.find('.//{http://www.w3.org/2000/svg}svg'))
            identifiers.append(note.attrib['id'])
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_repeated_versions_keep_independent_click_targets(self):
        table = self.render(*(self.minimum_version('8.15.0', 'curl 8.18.0.') for _ in range(3)))
        targets = [button.attrib['popovertarget'] for button in table.findall('.//button')]
        self.assertEqual(3, len(set(targets)))
        self.assertEqual(set(targets), {note.attrib['id'] for note in table.findall('.//span[@popover]')})

    def test_hint_touch_target_does_not_raise_the_version_baseline(self):
        css = (ROOT / 'docs/assets/extra.css').read_text(encoding='utf-8')
        rule = re.search(r'\.md-typeset \.minimum-version-note\s*\{([^}]+)\}', css).group(1)
        self.assertIn('vertical-align: middle;', rule)
        self.assertIn('min-height: 1.2rem;', rule)
        self.assertIn('min-width: 1.2rem;', rule)

    def test_version_and_tested_description_are_html_escaped(self):
        version = '8.15.0<script>alert("version")</script>'
        tested = 'curl "8.18.0" <img src=x onerror="alert(1)"> & others.'
        table = self.render(self.minimum_version(version, tested))
        self.assertEqual(version, table.find('.//code').text)
        self.assertIn(tested, table.find('.//button').attrib['title'])
        self.assertIn(tested, table.find('.//span[@popover]').text)
        self.assertIsNone(table.find('.//script'))
        self.assertIsNone(table.find('.//img'))

    def test_http_matrix_marks_every_minimum_and_discloses_untested_macos(self):
        page = (ROOT / 'docs/reference/connection/http/index.md').read_text(encoding='utf-8')
        matrix = page.split('### curl transport capabilities', 1)[1]
        self.assertIn('| Transport | Minimum version |', matrix)
        calls = re.findall(r'<<minimum_version\("([^"]+)", "([^"]+)"\)>>', matrix)
        self.assertEqual(['8.15.0', '8.16.0'], [version for version, _ in calls])
        for _, tested in calls:
            self.assertIn('curl 8.18.0 on Linux', tested)
            self.assertIn('curl 8.22.0 on Windows', tested)
            self.assertIn('macOS has not been tested natively.', tested)
        self.assertIn('failed concurrent duplex', calls[1][1])
        self.assertIn('unsuitable for SSH over WSS', calls[1][1])
