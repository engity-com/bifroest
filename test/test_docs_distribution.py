import copy
import json
import os
import re
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from xml.etree import ElementTree

import jinja2
import markdown
from material.extensions.emoji import to_svg, twemoji


ROOT = Path(__file__).resolve().parents[1]


class MacroEnvironment:
    def __init__(self):
        self.macros = {}
        files = SimpleNamespace(get_file_from_path=lambda name: SimpleNamespace(src_path=name))
        self.variables = SimpleNamespace(files=files)
        self.page = SimpleNamespace(file=SimpleNamespace(src_path='setup/distribution.md'))

    def macro(self, function):
        self.macros[function.__name__] = function
        return function


class DocsDistributionTest(TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {
            'VERSION': '1.2.3-beta1',
            'RELEASE_MANIFEST_FILE': '',
            'RELEASE_ASSETS_FILE': '',
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.module = run_path(str(ROOT / 'docs/.theme/marcos/main.py'))
        self.environment = MacroEnvironment()
        self.module['define_env'](self.environment)
        self.macros = self.environment.macros
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def manifest(self, schema=2):
        manifest = self.module['fallback_release_manifest']()
        manifest['schemaVersion'] = schema
        names = set()
        for variant in manifest['variants']:
            names.add(variant['archive'])
            for subject in variant['sboms'].values():
                names.update(subject.values())
            if schema == 1:
                variant['notice'] = variant['archive'].rsplit('.', 1)[0] + '.third-party-notices.txt'
                names.add(variant['notice'])
        manifest['assets'] = [{'name': name} for name in sorted(names)]
        return manifest

    def write_manifest(self, manifest, published=None):
        filename = self.directory / 'manifest.json'
        filename.write_text(json.dumps(manifest), encoding='utf-8')
        os.environ['RELEASE_MANIFEST_FILE'] = str(filename)
        if published is None:
            published = {a['name'] for a in manifest['assets']} | {manifest['manifestAsset'], manifest['checksumAsset']}
        inventory = self.directory / 'assets.txt'
        inventory.write_text('\n'.join(sorted(published)), encoding='utf-8')
        os.environ['RELEASE_ASSETS_FILE'] = str(inventory)

    def test_manifest_without_notice_assets_matches_the_published_inventory(self):
        manifest = self.manifest()
        self.write_manifest(manifest)
        self.assertEqual(manifest, self.module['load_release_manifest']())
        self.assertEqual(14, len(manifest['variants']))
        self.assertEqual(62, len(manifest['assets']))
        self.assertFalse(any('notice' in variant for variant in manifest['variants']))

    def test_published_v1_manifests_remain_readable_without_notice_download_links(self):
        manifest = self.manifest(schema=1)
        self.write_manifest(manifest)
        self.assertEqual(manifest, self.module['load_release_manifest']())
        table = ''.join(self.macros['compliance_matrix'](packaging=p) for p in ['archive', 'image'])
        self.assertNotIn('Notice', table)
        self.assertNotIn('.third-party-notices.txt', table)
        for variant in manifest['variants']:
            for subject in variant['sboms'].values():
                for name in subject.values():
                    self.assertIn('/v1.2.3-beta1/' + name, table)

    def test_archive_downloads_use_manifest_names_and_the_exact_release_tag(self):
        manifest = self.manifest()
        variant = manifest['variants'][0]
        previous = variant['archive']
        variant['archive'] = 'custom-archive-name.tgz'
        next(a for a in manifest['assets'] if a['name'] == previous)['name'] = variant['archive']
        self.write_manifest(manifest)
        table = self.macros['compatibility_matrix'](packaging='archive', downloads=True)
        rendered = markdown.markdown(
            table, extensions=['extra', 'pymdownx.emoji'],
            extension_configs={'pymdownx.emoji': {'emoji_index': twemoji, 'emoji_generator': to_svg}},
        )
        root = ElementTree.fromstring(rendered)
        rows = root.findall('./tbody/tr')
        self.assertEqual(6, len(rows))
        self.assertEqual(['Architecture', 'Linux', 'macOS', 'Windows'], [''.join(c.itertext()) for c in root.findall('./thead/tr/th')])
        self.assertEqual(['386', 'amd64', 'armv6', 'armv7', 'arm64', 'riscv64'], [''.join(row.find('td').itertext()) for row in rows])
        urls = []
        for row in rows:
            arch = row.find('td/code').text
            cells = row.findall('td')
            self.assertEqual(4, len(cells))
            for cell, target_os in zip(cells[1:], ['linux', 'darwin', 'windows']):
                icons = list(cell)
                self.assertEqual(['generic', 'extended'], [icon.attrib['data-edition'] for icon in icons])
                for icon in icons:
                    self.assertEqual(icon.attrib['title'], icon.attrib['aria-label'])
                    self.assertIn(arch, icon.attrib['title'])
                    self.assertIn(icon.attrib['data-edition'].title(), icon.attrib['title'])
                    self.assertIsNotNone(icon.find('.//{http://www.w3.org/2000/svg}svg'))
                    variant = next((v for v in manifest['variants'] if (v['os'], v['architecture'], v['edition']) == (target_os, arch, icon.attrib['data-edition'])), None)
                    if variant is None:
                        self.assertEqual('span', icon.tag)
                        self.assertEqual('none', icon.attrib['data-supported'])
                        self.assertNotIn('href', icon.attrib)
                    else:
                        self.assertEqual('a', icon.tag)
                        self.assertTrue(icon.attrib['href'].endswith('/' + variant['archive']))
                        urls.append(icon.attrib['href'])
        self.assertEqual(14, len(urls))
        self.assertEqual(
            {'https://github.com/engity-com/bifroest/releases/download/v1.2.3-beta1/' + v['archive'] for v in manifest['variants']},
            set(urls),
        )
        self.assertNotIn('/latest/', table)
        self.assertNotIn('.third-party-notices.txt', table)

    def test_archive_downloads_can_be_filtered_by_operating_system(self):
        table = self.macros['compatibility_matrix'](os='darwin', packaging='archive', downloads=True)
        self.assertEqual(2, table.count(':octicons-download-24:'))
        self.assertEqual(2, table.count(':octicons-circle-24:'))
        self.assertNotIn('bifroest-linux-', table)
        with self.assertRaisesRegex(ValueError, 'archive packaging'):
            self.macros['compatibility_matrix'](packaging='image', downloads=True)

    def test_distribution_tables_use_consistent_platform_names(self):
        for packaging, downloads in [(None, False), ('image', False), ('archive', False), ('archive', True)]:
            with self.subTest(packaging=packaging, downloads=downloads):
                table = self.macros['compatibility_matrix'](packaging=packaging, downloads=downloads)
                root = ElementTree.fromstring(markdown.markdown(table, extensions=['extra']))
                self.assertEqual(
                    ['Architecture', 'Linux', 'macOS', 'Windows'],
                    [''.join(cell.itertext()) for cell in root.findall('./thead/tr')[0]],
                )
        for packaging in ['archive', 'image']:
            table = self.macros['compliance_matrix'](packaging=packaging)
            root = ElementTree.fromstring(markdown.markdown(table, extensions=['extra']))
            self.assertEqual(
                ['Architecture', 'Linux', 'macOS', 'Windows'],
                [''.join(cell.itertext()) for cell in root.findall('./thead/tr')[0]],
            )

    def test_compliance_matrices_pair_editions_without_losing_artifact_links(self):
        manifest = self.manifest()
        self.write_manifest(manifest)
        downloads = []
        references = []
        for packaging in ['archive', 'image']:
            with self.subTest(packaging=packaging):
                table = self.macros['compliance_matrix'](packaging=packaging)
                rendered = markdown.markdown(
                    table, extensions=['extra', 'pymdownx.emoji'],
                    extension_configs={'pymdownx.emoji': {'emoji_index': twemoji, 'emoji_generator': to_svg}},
                )
                root = ElementTree.fromstring(rendered)
                self.assertEqual(packaging, root.attrib['data-packaging'])
                labels = ['Download', 'SPDX', 'CycloneDX'] if packaging == 'archive' else ['Reference', 'SPDX', 'CycloneDX']
                self.assertEqual(labels * 3, [cell.text for cell in root.findall('./thead/tr')[1]])
                rows = root.findall('./tbody/tr')
                self.assertEqual(6, len(rows))
                for row in rows:
                    arch = row.find('td/code').text
                    cells = row.findall('td')
                    self.assertEqual(10, len(cells))
                    for index, cell in enumerate(cells[1:]):
                        target_os = ['linux', 'darwin', 'windows'][index // 3]
                        column = index % 3
                        icons = list(cell)
                        self.assertEqual(['generic', 'extended'], [icon.attrib['data-edition'] for icon in icons])
                        for icon in icons:
                            edition = icon.attrib['data-edition']
                            self.assertEqual(icon.attrib['title'], icon.attrib['aria-label'])
                            self.assertIn(arch, icon.attrib['title'])
                            self.assertIn(edition.title(), icon.attrib['title'])
                            self.assertIsNotNone(icon.find('.//{http://www.w3.org/2000/svg}svg'))
                            variant = next((v for v in manifest['variants'] if (v['os'], v['architecture'], v['edition']) == (target_os, arch, edition)), {})
                            if column == 0 and packaging == 'archive':
                                expected = variant.get('archive')
                            elif column == 0:
                                expected = variant.get('image', {}).get('tag')
                            else:
                                expected = variant.get('sboms', {}).get(packaging, {}).get(['spdx', 'cycloneDx'][column - 1])
                            if not expected:
                                self.assertEqual('span', icon.tag)
                                self.assertNotIn('href', icon.attrib)
                                self.assertEqual('none', icon.attrib['data-supported'])
                            elif packaging == 'image' and column == 0:
                                self.assertEqual(expected, icon.attrib['data-reference'])
                                self.assertIn('navigator.clipboard.writeText', icon.attrib['onclick'])
                                references.append(expected)
                            else:
                                self.assertEqual('https://github.com/engity-com/bifroest/releases/download/v1.2.3-beta1/' + expected, icon.attrib['href'])
                                downloads.append(expected)
        self.assertEqual(10, len(references))
        self.assertCountEqual([asset['name'] for asset in manifest['assets']], downloads)

    def test_compliance_reference_buttons_preserve_immutable_platform_digests(self):
        manifest = self.manifest()
        variant = next(v for v in manifest['variants'] if v['os'] == 'linux' and v['architecture'] == 'amd64' and v['edition'] == 'extended')
        digest = 'sha256:' + 'a' * 64
        variant['image']['platformDigest'] = digest
        variant['image']['platformReference'] = 'ghcr.io/engity-com/bifroest@' + digest
        self.write_manifest(manifest)
        table = self.macros['compliance_matrix'](packaging='image')
        root = ElementTree.fromstring(markdown.markdown(table, extensions=['extra']))
        reference = variant['image']['tag'] + '@' + digest
        button = next(link for link in root.findall('.//a') if link.attrib.get('data-reference') == reference)
        self.assertIn(reference, button.attrib['title'])
        self.assertEqual('https://github.com/engity-com/bifroest/pkgs/container/bifroest?tag=extended-1.2.3-beta1', button.attrib['href'])
        with self.assertRaises(ValueError):
            self.macros['compliance_matrix'](packaging='unknown')

    def test_friendly_platform_names_keep_technical_anchors_and_identifiers(self):
        self.assertIn('[macOS]', self.macros['dist']('darwin'))
        self.assertIn('#darwin)', self.macros['dist']('darwin'))
        self.assertIn('[macOS/Generic]', self.macros['dist']('darwin', 'generic'))
        self.assertIn('#darwin-generic)', self.macros['dist']('darwin', 'generic'))
        self.assertIn('macOS', self.macros['compatibility'](True, 'generic', 'darwin'))
        self.assertNotIn('darwin', self.macros['compatibility'](True, 'generic', 'darwin'))
        self.assertEqual('darwin', self.module['Os'].darwin.value)

    def test_release_links_use_the_tag_route_and_keep_latest_working(self):
        self.assertEqual(
            'https://github.com/engity-com/bifroest/releases/tag/v1.2.3-beta1',
            self.macros['release_url'](),
        )
        self.assertEqual(
            'https://github.com/engity-com/bifroest/releases/latest',
            self.macros['release_url']('latest'),
        )

    def test_inventory_still_rejects_missing_and_unexpected_downloads(self):
        for schema in [1, 2]:
            manifest = self.manifest(schema)
            published = {a['name'] for a in manifest['assets']} | {manifest['manifestAsset'], manifest['checksumAsset']}
            for name in [manifest['variants'][0]['archive'], manifest['variants'][0]['sboms']['archive']['spdx']]:
                with self.subTest(schema=schema, missing=name):
                    self.write_manifest(manifest, published - {name})
                    with self.assertRaisesRegex(Exception, 'release is missing assets'):
                        self.module['load_release_manifest']()
            with self.subTest(schema=schema, unexpected=True):
                self.write_manifest(manifest, published | {'unexpected-notice.txt'})
                with self.assertRaisesRegex(Exception, 'release has unexpected assets'):
                    self.module['load_release_manifest']()

    def test_variant_and_sbom_validation_is_not_relaxed(self):
        original = self.manifest()
        for failure in ['missing archive', 'missing SBOM', 'duplicate variant', 'unknown asset', 'wrong version', 'wrong schema']:
            with self.subTest(failure=failure):
                manifest = copy.deepcopy(original)
                if failure == 'missing archive':
                    del manifest['variants'][0]['archive']
                elif failure == 'missing SBOM':
                    del manifest['variants'][0]['sboms']['archive']['spdx']
                elif failure == 'duplicate variant':
                    manifest['variants'].append(manifest['variants'][0])
                elif failure == 'unknown asset':
                    manifest['variants'][0]['archive'] = 'missing.tgz'
                elif failure == 'wrong version':
                    manifest['version'] = 'v9.9.9'
                else:
                    manifest['schemaVersion'] = 99
                self.write_manifest(manifest)
                with self.assertRaises(Exception):
                    self.module['load_release_manifest']()

    def test_distribution_page_leads_with_downloads_and_keeps_section_anchors(self):
        page = (ROOT / 'docs/setup/distribution.md').read_text(encoding='utf-8')
        self.assertLess(page.index('downloads=True'), page.index('## Platforms and editions'))
        self.assertIn('on-host.md', page)
        self.assertIn('in-docker.md', page)
        self.assertIn('in-kubernetes.md', page)
        archives = page.split('### Archives {: #archive }', 1)[1].split('### OCI/Docker Images', 1)[0]
        self.assertIn('[Setup Bifröst](github-actions.md)', archives)
        self.assertIn('adds the executable to `PATH`', archives)
        self.assertIn('| GitHub Actions job |', page)
        self.assertNotIn('bifroest-linux-<arch>', page)
        self.assertNotIn('.third-party-notices.txt', page)
        expected = {
            'packaging', 'archive', 'archive-matrix', 'archive-syntax', 'archive-examples',
            'image', 'image-matrix', 'image-syntax', 'image-examples', 'helm', 'compatibility',
            'os', 'linux', 'linux-generic', 'linux-extended', 'darwin', 'darwin-generic',
            'darwin-extended', 'windows', 'windows-generic', 'windows-extended', 'compliance',
        }
        anchors = set(re.findall(r'id="([^"]+)"', page)) | set(re.findall(r'\{:\s*#([^\s}]+)', page))
        self.assertLessEqual(expected, anchors)

    def test_rendered_examples_select_the_documentation_release(self):
        page = (ROOT / 'docs/setup/distribution.md').read_text(encoding='utf-8')
        template = jinja2.Environment(
            variable_start_string='<<', variable_end_string='>>',
            block_start_string='<%', block_end_string='%>', undefined=jinja2.StrictUndefined,
        ).from_string(page)
        rendered = template.render(**self.macros)
        self.assertIn('docker pull ghcr.io/engity-com/bifroest:generic-1.2.3-beta1', rendered)
        self.assertIn('docker pull ghcr.io/engity-com/bifroest:extended-1.2.3-beta1', rendered)
        self.assertIn('helm pull oci://ghcr.io/engity-com/bifroest --version 1.2.3-beta1', rendered)
        self.assertNotIn('--version latest', rendered)
        self.assertNotIn('releases/latest/download', rendered)

    def test_contributing_guidelines_are_aligned(self):
        root = (ROOT / 'CONTRIBUTING.md').read_text(encoding='utf-8')
        guide = (ROOT / 'docs/community/contributing.md').read_text(encoding='utf-8')
        guide = re.sub(r'^---\n.*?\n---\n', '', guide, count=1, flags=re.DOTALL)
        guide = guide.replace('<<asset_link("CLA.md", "Contributor License Agreement")>>', '[Contributor License Agreement](CLA.md)')
        guide = guide.replace('(../setup/upgrade.md)', '(docs/setup/upgrade.md)')
        self.assertEqual(root.strip(), guide.strip())

    def test_release_process_addresses_contributors_not_release_operators(self):
        for filename in ['CONTRIBUTING.md', 'docs/community/contributing.md']:
            with self.subTest(filename=filename):
                text = (ROOT / filename).read_text(encoding='utf-8')
                release = text.split('### Release process\n', 1)[1]
                self.assertIn('maintainers decide', release)
                self.assertIn('with your PR', release)
                self.assertIn('You do not need to create release tags', release)
                self.assertIn('https://github.com/engity-com/bifroest/releases', release)
                for instruction in ['#### Creation', '#### Validation', 'vX.Y.Z', 'release train', '```', 'mise run', 'https://echocat.org']:
                    self.assertNotIn(instruction, text)
