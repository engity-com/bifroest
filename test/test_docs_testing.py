from pathlib import Path
import ast
import re
from unittest import TestCase

import yaml


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'


def property_definitions(text):
    for match in re.finditer(r'<<property\((.*?)\)>>', text, re.DOTALL):
        call = ast.parse(f'property({match.group(1)})', mode='eval').body
        options = {item.arg: ast.literal_eval(item.value) for item in call.keywords}
        name = ast.literal_eval(call.args[0])
        yield match.start(), call, options, options.get('id_prefix', '') + 'property-' + name


class TestingDocumentationTest(TestCase):
    def test_every_testing_page_is_in_navigation(self):
        config = yaml.load((ROOT / 'mkdocs.yml').read_text(), Loader=yaml.BaseLoader)

        def destinations(node):
            if isinstance(node, str):
                yield node
            elif isinstance(node, dict):
                for value in node.values():
                    yield from destinations(value)
            elif isinstance(node, list):
                for value in node:
                    yield from destinations(value)

        pages = list(destinations(config['nav']))
        expected = ['guides/testing.md', 'reference/cli/test.md']
        expected += [p.relative_to(DOCS).as_posix() for p in (DOCS / 'reference/testing').glob('*.md')]
        for page in expected:
            with self.subTest(page=page):
                self.assertEqual(pages.count(page), 1)

    def test_cli_follows_command_reference_structure(self):
        text = (DOCS / 'reference/cli/test.md').read_text()
        for heading in ('Syntax', 'Arguments', 'Flags', 'Output', 'Examples', 'Availability'):
            self.assertIn(f'## {heading}', text)
        self.assertIn('<<cli_syntax("test",', text)
        self.assertIn('<<cli_availability(', text)
        self.assertNotIn('```lua', text)
        self.assertIn('../../guides/testing.md', text)
        self.assertIn('../testing/index.md', text)

    def test_testing_links_resolve_to_real_sources(self):
        pages = [DOCS / 'guides/testing.md', DOCS / 'reference/cli/test.md', ROOT / 'test/policyci/README.md']
        pages += list((DOCS / 'reference/testing').glob('*.md'))
        pages += list((ROOT / 'pkg/test').rglob('README.md'))
        for page in pages:
            for target in re.findall(r'\]\(([^)]+)\)', page.read_text()):
                if '://' in target or target.startswith('#'):
                    continue
                filename = target.split('#', 1)[0]
                with self.subTest(page=page, target=target):
                    self.assertTrue((page.parent / filename).is_file())

    def test_overview_selects_external_configuration_and_discovers_directory(self):
        overview = (DOCS / 'reference/testing/index.md').read_text()
        yaml_marker = '```yaml title="configuration.yaml"'
        lua_marker = '```lua title="access_bftest.lua"'
        self.assertLess(overview.index(yaml_marker), overview.index(lua_marker))
        suite = re.search(re.escape(lua_marker) + r'\n(.*?)\n```', overview, re.DOTALL).group(1)
        self.assertNotRegex(suite, re.compile(r'^\s*configuration\s*=', re.MULTILINE))
        self.assertNotIn('file_content', suite)
        self.assertIn('```shell\nbifroest test -c configuration.yaml .\n```', overview)

    def test_guide_selects_the_deployment_configuration_at_invocation(self):
        guide = (DOCS / 'guides/testing.md').read_text()
        suite = re.search(r'```lua title="tests/access_bftest.lua"\n(.*?)\n```', guide, re.DOTALL).group(1)
        self.assertNotRegex(suite, re.compile(r'^\s*configuration\s*=', re.MULTILINE))
        self.assertNotIn('file_content', suite)
        self.assertIn('```yaml title="configuration.yaml"', guide)
        commands = re.findall(r'\bbifroest test tests[^\n`]*', guide)
        self.assertTrue(commands)
        for command in commands:
            self.assertIn('--configuration configuration.yaml', command)

    def test_examples_are_owned_by_the_test_package(self):
        for directory in ('ssh', 'oidc', 'http'):
            self.assertTrue(list((ROOT / 'pkg/test/examples' / directory).glob('*_bftest.lua')))
        self.assertFalse((ROOT / 'pkg/policytest').is_dir() and list((ROOT / 'pkg/policytest').glob('*.go')))
        for page in [DOCS / 'guides/testing.md', DOCS / 'reference/cli/test.md', *list((DOCS / 'reference/testing').glob('*.md'))]:
            self.assertNotRegex(page.read_text(), r'test/policy(?:/|-(?:oidc|http))')

    def test_lua_checks_are_repository_tools_not_cli_features(self):
        config = (ROOT / 'mise.toml').read_text()
        self.assertIn('[tasks."lint:lua"]', config)
        self.assertIn('[tasks."format:lua"]', config)
        self.assertIn('luacheck --config .luacheckrc --no-default-config pkg/test', config)
        self.assertIn('stylua --config-path .stylua.toml --check pkg/test', config)
        workflow = yaml.load((ROOT / '.github/workflows/build.yml').read_text(), Loader=yaml.BaseLoader)
        job = workflow['jobs']['lint-lua']
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertTrue(any(step.get('run') == 'mise run lint:lua' for step in job['steps']))
        for step in job['steps']:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'@[a-f0-9]{40}$')
            self.assertNotEqual(step.get('continue-on-error'), 'true')

    def test_lua_reference_uses_existing_typed_property_style(self):
        config = yaml.load((ROOT / 'mkdocs.yml').read_text(), Loader=yaml.BaseLoader)
        toc = next(extension['toc'] for extension in config['markdown_extensions'] if isinstance(extension, dict) and 'toc' in extension)
        maximum_heading = int(toc['toc_depth'])

        def properties(page):
            text = (DOCS / 'reference/testing' / page).read_text()
            result = {}
            for _, call, keywords, _ in property_definitions(text):
                name = ast.literal_eval(call.args[0])
                prefix = keywords.get('id_prefix', '')
                self.assertGreaterEqual(len(call.args), 2, (page, name))
                self.assertIn(keywords['heading'], range(3, maximum_heading + 1), (page, name))
                self.assertNotIn(prefix + name, result, (page, prefix, name))
                result[prefix + name] = call
            return result

        for page in (DOCS / 'reference/testing').glob('*.md'):
            properties(page.name)

        groups = {
            'suites.md': ['name', 'configuration', 'environment', 'tests', 'platform', 'platform-os', 'platform-arch', 'platform-version'],
            'tests.md': ['name', 'input', 'verify'],
            'input.md': ['request', 'authentication', 'authentication-outcome', 'authentication-mode', 'authentication-account', 'authentication-oidc'],
            'context.md': ['input', 'environment', 'configuration', 'flows', 'flow-name'],
            'requests.md': ['requestingName', 'transport', 'method', 'host', 'slug'],
            'assertions.md': ['is-equal-expected', 'is-equal-actual', 'is-equal-reason'],
        }
        for page, names in groups.items():
            with self.subTest(page=page):
                self.assertEqual(set(properties(page)), set(names))

        model = (ROOT / 'pkg/test/model.go').read_text()
        oidc = (ROOT / 'pkg/authorization/assumed-oidc.go').read_text()
        mappings = [
            (model, 'input', 'input.md', ''),
            (model, 'assumption', 'input.md', 'authentication-'),
            (model, 'requestInput', 'requests.md', ''),
            (model, 'facts', 'local.md', ''),
            (model, 'account', 'local.md', 'account-'),
            (model, 'accountGroup', 'local.md', 'group-'),
            (model, 'localGroup', 'local.md', 'local-group-'),
            (oidc, 'AssumedOidcFacts', 'oidc.md', ''),
            (oidc, 'assumedOidcToken', 'oidc.md', 'token-'),
            (oidc, 'assumedOidcIDToken', 'oidc.md', 'id-token-'),
            (oidc, 'assumedOidcUserInfo', 'oidc.md', 'user-info-'),
        ]
        expected = {}
        for source, struct, page, prefix in mappings:
            match = re.search(r'type ' + struct + r' struct \{(.*?)\n\}', source, re.DOTALL)
            self.assertIsNotNone(match, struct)
            names = re.findall(r'json:"([^",]+)', match.group(1))
            expected.setdefault(page, set()).update(prefix + name for name in names)
        for page, names in expected.items():
            with self.subTest(page=page):
                self.assertEqual(set(properties(page)), names)

    def test_object_properties_use_separate_linked_type_sections(self):
        parents = {
            'suites.md': {'platform-': 'platform'},
            'tests.md': {},
            'input.md': {'authentication-': 'authentication'},
            'requests.md': {},
            'context.md': {'flow-': 'flow'},
            'local.md': {'account-': 'account', 'local-group-': 'local-group', 'group-': 'group'},
            'oidc.md': {'token-': 'token', 'id-token-': 'id-token', 'user-info-': 'user-info'},
            'result.md': {
                'request-': 'request', 'identity-': 'identity',
                'authentication-': 'authentication', 'ssh-': 'ssh-target',
                'local-': 'local-target', 'local-unix-': 'local-target',
                'local-windows-': 'local-target', 'unix-account-': 'unix-account',
                'unix-group-': 'unix-group', 'windows-group-': 'windows-group',
            },
        }
        for page, prefixes in parents.items():
            text = (DOCS / 'reference/testing' / page).read_text()
            self.assertIn('\n## Properties\n', text, page)
            # Code examples do not contribute headings to the rendered outline.
            outline = re.sub(r'(?ms)^```[^\n]*\n.*?^```$', '', text)
            definitions = list(property_definitions(outline))
            if page == 'suites.md':
                root_properties = [ast.literal_eval(call.args[0]) for _, call, options, _ in definitions if not options.get('id_prefix')]
                self.assertEqual(root_properties, ['name', 'configuration', 'environment', 'tests', 'platform'])
            events = [(offset, options['heading'], anchor, options) for offset, _, options, anchor in definitions]
            for match in re.finditer(r'^(#{1,6}) (.+)$', outline, re.MULTILINE):
                title = match.group(2)
                explicit = re.search(r'\{:\s*#([^\s}]+)', title)
                anchor = explicit.group(1) if explicit else title.lower().replace(' ', '-')
                events.append((match.start(), len(match.group(1)), anchor, None))
            stack = []
            for _, level, anchor, options in sorted(events):
                while stack and stack[-1][0] >= level:
                    stack.pop()
                if options is not None:
                    expected = prefixes.get(options.get('id_prefix', ''), 'properties')
                    if page == 'context.md' and anchor == 'property-flows':
                        expected = 'configuration'
                    with self.subTest(page=page, property=anchor):
                        self.assertTrue(stack)
                        self.assertEqual(stack[-1], (level - 1, expected))
                stack.append((level, anchor))
            last_property = max(offset for offset, _, _, _ in definitions)
            for match in re.finditer(r'^## (?:Examples?|Denial example|Configuration fallback|Names and filters|Visibility and absence)\b', outline, re.MULTILINE):
                self.assertGreater(match.start(), last_property, (page, match.group()))

        suites = (DOCS / 'reference/testing/suites.md').read_text()
        self.assertIn('# Suites {: #suite }', suites)
        self.assertNotRegex(suites, re.compile(r'^## (?:Suite|Test)\s*\{', re.MULTILINE))
        self.assertIn('## Platform {: #platform }', suites)
        self.assertIn('array_ref("Test", "tests.md#test")', suites)
        self.assertNotIn('#names', suites)
        self.assertNotIn('## Names', suites)

    def test_shared_value_types_are_direct_property_type_links(self):
        expected = {
            'suites.md': {
                'property-name': ('Name', 'name'),
                'platform-property-os': ('OS selector', 'os-selector'),
                'platform-property-arch': ('Architecture selector', 'architecture-selector'),
                'platform-property-version': ('Version selector', 'version-selector'),
            },
            'tests.md': {'property-name': ('Name', 'name')},
            'input.md': {
                'authentication-property-outcome': ('Authentication outcome', 'authentication-outcome'),
                'authentication-property-mode': ('Authentication mode', 'authentication-mode'),
            },
            'requests.md': {
                'property-requestingName': ('Requesting name', 'requesting-name'),
                'property-transport': ('Transport', 'transport'),
                'property-method': ('Authentication method', 'authentication-method'),
                'property-host': ('Server authority', 'server-authority'),
                'property-slug': ('Slug', 'slug'),
            },
            'oidc.md': {prefix + 'property-' + field: ('UTC timestamp', 'utc-timestamp') for prefix, field in [('token-', 'expiry'), ('id-token-', 'expiry'), ('id-token-', 'issuedAt')]},
            'local.md': {
                'account-property-uid': ('Unix ID', 'unix-id'),
                'group-property-gid': ('Unix ID', 'unix-id'),
                'local-group-property-members': ('SID', 'sid'),
            },
            'result.md': {
                'property-decision': ('Decision', 'decision'),
                'authentication-property-mode': ('Authentication mode', 'authentication-mode'),
                'request-property-transport': ('Transport', 'transport'),
                'request-property-method': ('Authentication method', 'authentication-method'),
                'request-property-requestingName': ('Requesting name', 'requesting-name'),
                'request-property-slug': ('Slug', 'slug'),
            },
        }
        for page, types in expected.items():
            calls = {anchor: call for _, call, _, anchor in property_definitions((DOCS / 'reference/testing' / page).read_text())}
            for anchor, (title, target) in types.items():
                call = calls[anchor]
                arguments = call.args[1].args if isinstance(call.args[1], ast.Call) else call.args[1:]
                with self.subTest(page=page, property=anchor):
                    self.assertEqual(ast.literal_eval(arguments[0]), title)
                    self.assertEqual(ast.literal_eval(arguments[1]), 'data-types.md#' + target)

    def test_test_and_input_pages_are_unambiguous(self):
        for filename, title in [('tests.md', 'Tests'), ('input.md', 'Input')]:
            self.assertIn('# ' + title + ' {:', (DOCS / 'reference/testing' / filename).read_text())
            self.assertIn('- ' + title + ': reference/testing/' + filename, (ROOT / 'mkdocs.yml').read_text())
        for page in [DOCS / 'guides/testing.md', DOCS / 'reference/cli/test.md', *list((DOCS / 'reference/testing').glob('*.md'))]:
            self.assertNotIn('experimental', page.read_text().lower(), page)
        self.assertIn('```lua title="access_bftest.lua"', (DOCS / 'reference/testing/index.md').read_text())

    def test_suite_fields_match_runtime_without_a_format_version(self):
        text = (DOCS / 'reference/testing/suites.md').read_text()
        names = {ast.literal_eval(call.args[0]) for _, call, options, _ in property_definitions(text) if not options.get('id_prefix')}
        register = (ROOT / 'pkg/test/lua.go').read_text().split('func (s *luaState) register(', 1)[1]
        keys = re.search(r's\.checkKeys\(table, (.*?)\)', register).group(1)
        self.assertEqual(names, set(re.findall(r'"([^"]+)"', keys)))
        self.assertNotIn('apiVersion', names)
        pages = [DOCS / 'guides/testing.md', *list((DOCS / 'reference/testing').glob('*.md'))]
        for page in pages:
            for block in re.findall(r'(?ms)^```lua[^\n]*\n(.*?)^```$', page.read_text()):
                self.assertNotIn('apiVersion', block, page)
        for page in (ROOT / 'pkg/test').rglob('*.lua'):
            self.assertNotIn('apiVersion', page.read_text(), page)

    def test_functions_have_argument_return_and_example_sections(self):
        text = (DOCS / 'reference/testing/lua.md').read_text()
        for name in ('suite', 'object', 'list', 'file_content'):
            start = text.index(f'## `{name}(')
            section = text[start:].split('\n## ', 1)[0]
            self.assertIn('### Arguments', section, name)
            self.assertIn('### Return value', section, name)
            self.assertTrue('### Example' in section or 'properties and example' in section, name)
        text = (DOCS / 'reference/testing/assertions.md').read_text()
        for heading in ('Arguments', 'Return value', 'Errors', 'Example'):
            self.assertIn('### ' + heading, text)

    def test_operator_reference_does_not_describe_private_go_implementation(self):
        pages = ['index.md', 'lua.md', 'suites.md', 'input.md', 'requests.md', 'local.md', 'oidc.md', 'context.md', 'result.md', 'assertions.md']
        for name in pages:
            text = (DOCS / 'reference/testing' / name).read_text()
            for private in ('finalizeAuth', 'ProjectLocalUnixTarget', 'ProjectLocalWindowsTarget', 'BindAssumedOidcAuthentication', 'facade entry', 'nil-valued getters'):
                with self.subTest(page=name, private=private):
                    self.assertNotIn(private, text)
