from pathlib import Path
import re
from unittest import TestCase
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
PAGE = DOCS / 'concept.md'


def documentation_url(page):
    route = page.relative_to(DOCS).with_suffix('')
    if route.name == 'index':
        route = route.parent
    return f'https://bifroest.engity.org/{"/".join(route.parts)}'.rstrip('/') + '/'


class ConceptDocumentationTest(TestCase):
    def test_concept_has_valid_page_metadata(self):
        metadata = yaml.safe_load(PAGE.read_text().split('---', 2)[1])
        self.assertIsInstance(metadata['description'], str)
        self.assertTrue(metadata['description'])

    def test_concept_follows_welcome_in_home_navigation(self):
        config = yaml.load((ROOT / 'mkdocs.yml').read_text(), Loader=yaml.BaseLoader)
        home = next(item['Home'] for item in config['nav'] if 'Home' in item)
        self.assertEqual(home[:2], [
            {'Welcome': 'index.md'},
            {'Concept': 'concept.md'},
        ])

    def test_entry_points_link_to_concept(self):
        for page in (
            ROOT / 'README.md',
            DOCS / 'index.md',
            DOCS / 'choosing-bifroest.md',
            DOCS / 'setup/operations.md',
        ):
            targets = re.findall(r'\]\(([^)]+)\)', page.read_text())
            with self.subTest(page=page.relative_to(ROOT)):
                if page == ROOT / 'README.md':
                    self.assertIn(documentation_url(PAGE), targets)
                else:
                    self.assertTrue(any(
                        (page.parent / target.split('#', 1)[0]).resolve() == PAGE
                        for target in targets
                    ))

    def test_overviews_link_to_all_three_identity_sources(self):
        sources = (
            DOCS / 'reference/authorization/oidc/index.md',
            DOCS / 'reference/authorization/local.md',
            DOCS / 'reference/authorization/simple.md',
        )
        for page in (PAGE, ROOT / 'README.md', DOCS / 'index.md'):
            links = re.findall(r'\]\(([^)]+)\)', page.read_text())
            targets = {
                (page.parent / target.split('#', 1)[0]).resolve()
                for target in links
                if '://' not in target
            }
            for source in sources:
                with self.subTest(page=page.relative_to(ROOT), source=source):
                    if page == ROOT / 'README.md':
                        self.assertIn(documentation_url(source), links)
                    else:
                        self.assertIn(source, targets)

    def test_readme_documentation_links_use_rendered_site(self):
        links = re.findall(r'(?<!!)\[[^]]+\]\(([^)]+)\)', (ROOT / 'README.md').read_text())
        for target in links:
            with self.subTest(target=target):
                self.assertFalse(target.startswith('docs/'))
                url = urlsplit(target)
                if url.netloc != 'bifroest.engity.org':
                    continue
                self.assertEqual(url.scheme, 'https')
                self.assertTrue(url.path.endswith('/'))
                source = DOCS / url.path.strip('/')
                source = source / 'index.md' if source.is_dir() else source.with_suffix('.md')
                self.assertTrue(source.is_file())

    def test_setup_terms_link_to_operational_documentation(self):
        links = re.findall(r'\[([^]]+)\]\(([^)]+)\)', PAGE.read_text())
        expected = (
            ('Binary', 'setup/on-host.md'),
            ('container', 'setup/in-docker.md'),
            ('configuration', 'reference/configuration.md'),
            ('required keys', 'security.md#service-and-storage-permissions'),
            ('persistent storage', 'setup/operations.md#restart-and-recovery-checklist'),
        )
        for link in expected:
            with self.subTest(link=link):
                self.assertIn(link, links)

    def test_concept_links_resolve(self):
        targets = re.findall(r'\]\(([^)]+)\)', PAGE.read_text())
        for target in targets:
            if '://' in target or target.startswith('#'):
                continue
            with self.subTest(target=target):
                self.assertTrue((PAGE.parent / target.split('#', 1)[0]).is_file())
        self.assertIn('reference/testing/index.md#scope', targets)
        self.assertIn('setup/operations.md', targets)
        self.assertIn('usecases.md#offboard', targets)
