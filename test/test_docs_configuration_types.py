import ast
import re
import shlex
import textwrap
from pathlib import Path
from unittest import TestCase

import yaml


DOCS = Path(__file__).resolve().parents[1] / 'docs'


def properties(relative):
    text = (DOCS / relative).read_text(encoding='utf-8')
    return [
        ast.parse(f'property({match.group(1)})', mode='eval').body
        for match in re.finditer(r'<<property\((.*?)\)>>', text, re.DOTALL)
    ]


class DocsConfigurationTypesTest(TestCase):
    def test_monitoring_peer_filter_uses_a_shared_data_type(self):
        data_types = (DOCS / 'reference/data-type.md').read_text(encoding='utf-8')
        self.assertIn('## IP Address or Network {: #ip-address-or-network }', data_types)
        prop = next(call for call in properties('reference/monitoring.md') if ast.literal_eval(call.args[0]) == 'allowedRemoteHosts')
        reference = prop.args[1]
        self.assertIsInstance(reference, ast.Call)
        self.assertEqual('array_ref', reference.func.id)
        self.assertEqual('IP Address or Network', ast.literal_eval(reference.args[0]))
        self.assertEqual('data-type.md#ip-address-or-network', ast.literal_eval(reference.args[1]))

    def test_monitoring_reference_has_a_minimal_example_before_compatibility(self):
        text = (DOCS / 'reference/monitoring.md').read_text(encoding='utf-8')
        examples, compatibility = text.split('## Examples\n', 1)[1].split('## Compatibility\n', 1)
        self.assertNotRegex(examples, r'(?m)^## ')
        self.assertIn('<<compatibility_editions(', compatibility)
        block = re.search(r'```yaml\n(.*?)\n```', examples, re.DOTALL)
        self.assertIsNotNone(block)
        self.assertEqual({'monitoring': {'enabled': True}}, yaml.safe_load(block.group(1)))

    def test_ssh_tunnel_reference_links_directly_to_its_connection_guide(self):
        reference = (DOCS / 'reference/connection/http/index.md').read_text(encoding='utf-8')
        section = reference.split('## SSH tunnel\n\n', 1)[1].split('## Login flow', 1)[0]
        self.assertIn('](../../../guides/ssh-over-https.md)', section.split('\n\n', 1)[0])
        self.assertNotIn('ProxyCommand', section)
        self.assertIn('id_prefix="ssh-tunnel-"', section)
        self.assertIn('(ssh-over-https.md)', (DOCS / 'guides/index.md').read_text(encoding='utf-8'))
        self.assertIn('SSH over HTTPS: guides/ssh-over-https.md', (DOCS.parent / 'mkdocs.yml').read_text(encoding='utf-8'))

    def test_ssh_tunnel_guide_uses_short_curl_flags_and_the_openssh_hostname(self):
        guide = (DOCS / 'guides/ssh-over-https.md').read_text(encoding='utf-8')
        commands = re.findall(r'^\s*ProxyCommand (.+)$', guide, re.MULTILINE)
        self.assertEqual(2, len(commands))
        for command, method, scheme in zip(commands, ['POST', 'GET'], ['https', 'wss']):
            with self.subTest(method=method):
                args = shlex.split(command)
                self.assertEqual(['curl', '-q', '-fsSN'], args[:3])
                self.assertIn('--no-progress-meter', args)
                self.assertIn('--http1.1', args)
                self.assertEqual('.', args[args.index('-T') + 1])
                self.assertEqual(method, args[args.index('-X') + 1])
                self.assertIn('Expect:', args)
                self.assertEqual(f'{scheme}://%h/api/v1/ssh', args[-1])
                self.assertFalse({'--disable', '--silent', '--show-error', '--fail', '--no-buffer', '--upload-file', '--request', '--header', '--url'} & set(args))
                self.assertNotIn('-k', args)
        self.assertEqual(1, guide.count('bifroest.example.org'))
        self.assertIn('Windows curl 8.22.0/Schannel fails', guide)

    def test_remember_me_examples_only_configure_supported_authorizations(self):
        def check(node, page, path=()):
            if isinstance(node, dict):
                authorization = path and (path[-1] == 'authorization' or len(path) > 1 and path[-2] == 'authorizations')
                authorization = authorization or (not path and page.parent.name == 'authorization' and 'type' in node)
                if authorization:
                    if node.get('type') in ['none', 'bifroest']:
                        self.assertNotIn('rememberMe', node, f'{page}: {path}')
                    elif 'rememberMe' in node:
                        self.assertEqual('allowedAndEnabledByDefault', node['rememberMe'], f'{page}: {path}')
                for key, value in node.items():
                    check(value, page, path + (key,))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    check(value, page, path + (index,))
        for page in DOCS.rglob('*.md'):
            for block in re.findall(r'^\s*```yaml[^\n]*\n(.*?)^\s*```', page.read_text(encoding='utf-8'), re.MULTILINE | re.DOTALL):
                try:
                    value = yaml.safe_load(textwrap.dedent(block))
                except yaml.YAMLError:
                    continue
                check(value, page)
        root = DOCS.parent
        for directory in ['contrib/configurations', 'internal/build/images/contrib']:
            for page in (root / directory).glob('*.yaml'):
                check(yaml.safe_load(page.read_text(encoding='utf-8')), page)

    def test_id_conversion_documents_required_repeatable_argument(self):
        text = (DOCS / 'reference/cli/id/convert.md').read_text(encoding='utf-8')
        self.assertIn('<<cli_syntax("id convert", "[flags] <id>...")>>', text)
        self.assertIn('### `id` {: #argument-id }', text)
        self.assertIn('One or more required IDs', text)

    def test_browser_guide_uses_acme(self):
        text = (DOCS / 'guides/browser-access.md').read_text(encoding='utf-8')
        example = re.search(r'```yaml[^\n]*\n(.*?)\n```', text, re.DOTALL)
        self.assertIsNotNone(example)
        config = yaml.safe_load(example.group(1))
        tls = config['http'].get('tls', '')
        if isinstance(tls, str):
            tls = config['tls'][tls or 'default']
        self.assertNotIn('certificates', tls)
        self.assertNotIn('enabled', tls['acme'])
        self.assertTrue(tls['acme']['acceptTerms'])
        self.assertEqual([':443'], config['http']['addresses'])

    def test_tls_acme_reference_documents_each_property_with_defaults(self):
        expected = {
            'acceptTerms': ('bool', False),
            'email': ('string', ''),
            'directoryUrl': ('URL', 'https://acme-v02.api.letsencrypt.org/directory'),
            'storage': ('File Path', '<os specific>'),
        }
        documented = {}
        for call in properties('reference/transports/tls/index.md'):
            keywords = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
            if keywords.get('id_prefix') != 'acme-':
                continue
            name = ast.literal_eval(call.args[0])
            self.assertNotIn(name, documented)
            self.assertEqual(3, keywords['heading'])
            documented[name] = (ast.literal_eval(call.args[1]), keywords['default'])
        self.assertEqual(expected, documented)

    def test_tls_acme_storage_defaults_follow_the_session_storage_style(self):
        text = (DOCS / 'reference/transports/tls/index.md').read_text(encoding='utf-8')
        acme = text.split('## ACME\n', 1)[1].split('## Examples\n', 1)[0]
        sentence = 'The default value is different, depending on the platform Bifröst runs on:'
        session = (DOCS / 'reference/session/fs.md').read_text(encoding='utf-8')
        self.assertIn(sentence, session)
        self.assertIn(sentence, acme)
        for line in [
            '* Linux: `/var/lib/engity/bifroest/tls/<name>/acme`',
            '* macOS: `/Library/Application Support/Engity/Bifroest/tls/<name>/acme`',
            r'* Windows: `C:\ProgramData\Engity\Bifroest\tls\<name>\acme`',
        ]:
            self.assertIn(line, acme)
        self.assertNotIn('<<dist(', acme)

    def test_tls_certificate_defaults_are_complete_platform_specific_sets(self):
        text = (DOCS / 'reference/transports/tls/index.md').read_text(encoding='utf-8')
        section = text.split('<<property("certificates",', 1)[1].split('<<property("dummy",', 1)[0]
        self.assertIn('[`dummy`](#property-dummy)', section)
        self.assertIn('[`acme`](#property-acme)', section)
        self.assertIn('If no certificates are supplied', section)
        blocks = re.findall(r'(Linux|macOS|Windows):\n\n```yaml\n(.*?)\n```', section, re.DOTALL)
        expected = [
            ('Linux', '/etc/engity/bifroest/tls/tls.crt', '/etc/engity/bifroest/tls/tls.key'),
            ('macOS', '/Library/Application Support/Engity/Bifroest/tls/tls.crt', '/Library/Application Support/Engity/Bifroest/tls/tls.key'),
            ('Windows', r'C:\ProgramData\Engity\Bifroest\tls\tls.crt', r'C:\ProgramData\Engity\Bifroest\tls\tls.key'),
        ]
        self.assertEqual(3, len(blocks))
        for (platform, block), (name, certificate, key) in zip(blocks, expected):
            self.assertEqual(name, platform)
            self.assertEqual({'certificates': [{'certificateFile': certificate, 'privateKeyFile': key}]}, yaml.safe_load(block))

    def test_certificate_file_properties_are_required_without_individual_defaults(self):
        page = 'reference/transports/tls/index.md'
        text = (DOCS / page).read_text(encoding='utf-8')
        certificate = re.split(r'(?m)^#{2,3} Certificate\n', text, maxsplit=1)[1].split('\n## ', 1)[0]
        self.assertNotIn('The default value', certificate)
        for call in properties(page):
            keywords = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
            if keywords.get('id_prefix') == 'certificate-':
                self.assertTrue(keywords['required'])
                self.assertNotIn('default', keywords)

    def test_monitoring_links_to_shared_tls_without_a_detached_tls_section(self):
        text = (DOCS / 'reference/monitoring.md').read_text(encoding='utf-8')
        self.assertNotIn('## TLS\n', text)
        self.assertNotIn('### Certificate\n', text)
        calls = properties('reference/monitoring.md')
        prop = next(call for call in calls if ast.literal_eval(call.args[0]) == 'tls')
        self.assertEqual('TLS or name', ast.literal_eval(prop.args[1]))
        self.assertEqual('transports/tls/index.md', ast.literal_eval(prop.args[2]))
        self.assertFalse(any(ast.literal_eval(call.args[0]) in {'certificates', 'certificateFile', 'privateKeyFile'} for call in calls))
        for page in DOCS.rglob('*.md'):
            self.assertNotIn('monitoring.md#tls', page.read_text(encoding='utf-8'), page)

    def test_tls_reference_has_standard_properties_and_compatibility_after_examples(self):
        self.assertFalse((DOCS / 'reference/tls.md').exists())
        text = (DOCS / 'reference/transports/tls/index.md').read_text(encoding='utf-8')
        introduction = text.split('# TLS\n', 1)[1].split('## Properties\n', 1)[0]
        self.assertNotIn('```', introduction)
        self.assertLessEqual(len(introduction.strip().splitlines()), 3)
        self.assertIn('](../../connection/http/index.md#property-tls)', introduction)
        self.assertIn('](../../monitoring.md#property-tls)', introduction)
        self.assertNotIn('profile', text.lower())
        self.assertNotIn('## Named definitions\n', text)
        examples, compatibility = text.split('## Examples\n', 1)[1].split('## Compatibility\n', 1)
        self.assertNotRegex(examples, r'(?m)^## ')
        self.assertNotRegex(compatibility, r'(?m)^## ')
        names = set()
        for call in properties('reference/transports/tls/index.md'):
            keywords = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
            if not keywords.get('id_prefix'):
                names.add(ast.literal_eval(call.args[0]))
        self.assertEqual({'minVersion', 'certificates', 'dummy', 'reloadInterval', 'acme'}, names)
        for page in DOCS.rglob('*.md'):
            self.assertNotIn('allowedNames', page.read_text(encoding='utf-8'), page)
        minimum = next(call for call in properties('reference/transports/tls/index.md') if ast.literal_eval(call.args[0]) == 'minVersion')
        self.assertEqual('1.3', next(ast.literal_eval(keyword.value) for keyword in minimum.keywords if keyword.arg == 'default'))

    def test_tls_inline_and_referenced_examples_use_the_same_definition(self):
        text = (DOCS / 'reference/transports/tls/index.md').read_text(encoding='utf-8')
        examples = text.split('## Examples\n', 1)[1]
        blocks = re.findall(r'```yaml\n(.*?)\n```', examples, re.DOTALL)
        inline, referenced = [yaml.safe_load(block) for block in blocks[:2]]
        self.assertEqual(inline['http']['tls'], referenced['tls'][referenced['http']['tls']])

    def test_http_links_to_tls_without_a_detached_tls_section(self):
        text = (DOCS / 'reference/connection/http/index.md').read_text(encoding='utf-8')
        self.assertNotIn('## TLS\n', text)
        section = text.split('<<property("tls",', 1)[1].split('<<property("upstream",', 1)[0]
        self.assertNotIn('```', section)
        self.assertLessEqual(len(section.strip().splitlines()), 2)
        self.assertIn('### Load balancers and instance routing', text.split('## Upstream\n', 1)[1].split('## RememberMe\n', 1)[0])
        prop = next(call for call in properties('reference/connection/http/index.md') if ast.literal_eval(call.args[0]) == 'tls')
        self.assertEqual('TLS or name', ast.literal_eval(prop.args[1]))
        self.assertEqual('../../transports/tls/index.md', ast.literal_eval(prop.args[2]))

    def test_http_enabled_documents_application_and_alpn_only_modes(self):
        page = 'reference/connection/http/index.md'
        enabled = next(call for call in properties(page) if ast.literal_eval(call.args[0]) == 'enabled')
        self.assertEqual('bool or string', ast.literal_eval(enabled.args[1]))
        self.assertFalse(next(ast.literal_eval(keyword.value) for keyword in enabled.keywords if keyword.arg == 'default'))
        text = (DOCS / page).read_text(encoding='utf-8')
        section = text.split('<<property("enabled",', 1)[1].split('<<property("webUi",', 1)[0]
        for value in ['false', 'true', 'acmeTlsAlpnOnly']:
            self.assertIn(f'| `{value}` |', section)
        self.assertIn('no WebUI, API, SSH tunnel or OIDC endpoints', section)

    def test_http_examples_are_self_contained_and_link_to_the_helm_installation(self):
        text = (DOCS / 'reference/connection/http/index.md').read_text(encoding='utf-8')
        examples = text.split('## Examples\n', 1)[1].split('## Compatibility\n', 1)[0]
        self.assertEqual(
            ['HTTPS with ACME', 'SSH tunnels only', 'Behind a reverse proxy'],
            re.findall(r'^### (.+)$', examples, re.MULTILINE),
        )
        configurations = [yaml.safe_load(block) for block in re.findall(r'```yaml\n(.*?)\n```', examples, re.DOTALL)]
        self.assertEqual(3, len(configurations))
        self.assertTrue(configurations[0]['http']['tls']['acme']['acceptTerms'])
        tunnel = configurations[1]
        self.assertFalse(tunnel['ssh']['enabled'])
        self.assertFalse(tunnel['http']['webUi']['enabled'])
        self.assertFalse(tunnel['http']['loginFlow']['enabled'])
        self.assertTrue(tunnel['http']['tls']['acme']['acceptTerms'])
        self.assertIn('tls', configurations[2]['http'])
        self.assertIsNone(configurations[2]['http']['tls'])
        self.assertNotIn('helm upgrade', examples)
        self.assertIn('setup/in-kubernetes.md#http-ingress', examples)
        installation = (DOCS / 'setup/in-kubernetes.md').read_text(encoding='utf-8')
        ingress = installation.split('## HTTP ingress', 1)[1].split('## Direct ACME', 1)[0]
        self.assertIn('```yaml title="ingress-values.yaml"', ingress)
        self.assertIn('helm upgrade bifroest', ingress)

    def test_tls_alpn_only_example_uses_http_listener_configuration(self):
        text = (DOCS / 'reference/transports/tls/index.md').read_text(encoding='utf-8')
        self.assertNotIn('## Challenge listener\n', text)
        child = 'reference/transports/tls/challenge-listener.md'
        self.assertFalse((DOCS / child).exists())
        self.assertNotIn(child, (DOCS.parent / 'mkdocs.yml').read_text(encoding='utf-8'))
        self.assertIn('](../../connection/http/index.md#property-addresses)', text)
        for page in DOCS.rglob('*.md'):
            self.assertNotIn('tlsChallenge', page.read_text(encoding='utf-8'), page)
            self.assertNotIn('challenge-listener.md', page.read_text(encoding='utf-8'), page)
        example = text.split('### ACME without HTTP browser access\n', 1)[1]
        block = re.search(r'```yaml\n(.*?)\n```', example, re.DOTALL)
        config = yaml.safe_load(block.group(1))
        self.assertEqual('acmeTlsAlpnOnly', config['http']['enabled'])
        self.assertEqual(config['monitoring']['tls'], config['http']['tls'])
        self.assertTrue(config['monitoring']['enabled'])
        self.assertNotIn('enabled', config['tls'][config['monitoring']['tls']]['acme'])
        self.assertTrue(config['tls'][config['monitoring']['tls']]['acme']['acceptTerms'])
        self.assertEqual([':8443'], config['http']['addresses'])

    def test_flow_examples_show_equivalent_inline_and_referenced_configuration(self):
        text = (DOCS / 'reference/flow.md').read_text(encoding='utf-8')
        section = text.split('<<property("authorization",', 1)[1].split('<<property("environment",', 1)[0]
        blocks = re.findall(r'```yaml\n(.*?)\n```', section, re.DOTALL)
        self.assertEqual(2, len(blocks))
        inline, referenced = [yaml.safe_load(block) for block in blocks]
        flow = referenced['flows'][0]
        resolved = {
            **flow,
            'authorization': referenced['authorizations'][flow['authorization']],
            'environment': referenced['environments'][flow['environment']],
        }
        self.assertEqual(inline['flows'][0], resolved)

    def test_user_reference_has_no_http_implementation_or_unreleased_migration_sections(self):
        self.assertFalse((DOCS / 'reference/connection/http/security.md').exists())
        for page in DOCS.rglob('*.md'):
            text = page.read_text(encoding='utf-8')
            with self.subTest(page=page.relative_to(DOCS)):
                for removed in ['http/security.md', 'session-association-groundwork', '#current-connection']:
                    self.assertNotIn(removed, text)
        context = (DOCS / 'reference/context/local-environment.md').read_text(encoding='utf-8')
        self.assertIn('Includes the [Environment context](environment.md), plus:', context)
        http = (DOCS / 'reference/connection/http/index.md').read_text(encoding='utf-8')
        introduction = http.split('# HTTP connection', 1)[1].split('## Configuration', 1)[0]
        self.assertEqual(1, len(introduction.strip().split('\n\n', 1)[0].splitlines()))
        self.assertLessEqual(len(introduction.strip().splitlines()), 8)
        self.assertNotIn('<tab-id>', http)
        self.assertNotIn('Legacy', http)

    def test_windows_service_bootstrap_is_not_public_documentation(self):
        for relative in ['reference/cli/serve.md', 'reference/environment/local.md']:
            with self.subTest(page=relative):
                text = (DOCS / relative).read_text(encoding='utf-8')
                self.assertNotIn('windowsService', text)

    def test_remote_name_examples_belong_to_their_authorizations(self):
        self.assertFalse((DOCS / 'reference/authorization/login-name-mapping.md').exists())
        for kind in ['local', 'simple', 'htpasswd']:
            with self.subTest(authorization=kind):
                text = (DOCS / f'reference/authorization/{kind}.md').read_text(encoding='utf-8')
                self.assertNotIn('login-name-mapping.md', text)
                examples = text.split('## Examples', 1)[1]
                mapping = examples.split('### Login name with an SSH suffix', 1)[1]
                blocks = [yaml.safe_load(block) for block in re.findall(r'^```yaml\n(.*?)\n```$', mapping, re.DOTALL | re.MULTILINE)]
                mapped = [block for block in blocks if isinstance(block, dict) and 'remoteName' in block]
                self.assertEqual(1, len(mapped))
                self.assertEqual(kind, mapped[0]['type'])
                template = mapped[0]['remoteName'].strip()
                self.assertTrue(template.startswith('{{- if eq .connection.transport "ssh" -}}'))
                self.assertTrue(template.endswith('{{- end -}}'), 'A YAML block scalar must not retain a closing quote.')
                self.assertIn('regexReplaceAll "@[^@]+$" .remote.user ""', template)
                self.assertIn('{{- else -}}', template)

    def test_remember_me_uses_a_shared_data_type_not_a_common_property(self):
        data_types = (DOCS / 'reference/data-type.md').read_text(encoding='utf-8')
        self.assertIn('## RememberMe {: #rememberme }', data_types)
        for value in ['forbidden', 'allowed', 'allowedAndEnabledByDefault', 'enforced']:
            self.assertIn(f'`{value}`', data_types)
        for kind in ['local', 'simple', 'htpasswd', 'oidc/authorization-code', 'oidc/device-authorization']:
            prop = next(call for call in properties(f'reference/authorization/{kind}.md') if ast.literal_eval(call.args[0]) == 'rememberMe')
            self.assertEqual('RememberMe', ast.literal_eval(prop.args[1]))
            prefix = '../../' if kind.startswith('oidc/') else '../'
            self.assertEqual(prefix + 'data-type.md#rememberme', ast.literal_eval(prop.args[2]))
        for kind in ['index', 'none', 'bifroest']:
            self.assertNotIn('rememberMe', [ast.literal_eval(call.args[0]) for call in properties(f'reference/authorization/{kind}.md')])
        for page in DOCS.rglob('*.md'):
            self.assertNotIn('authorization/index.md#property-rememberMe', page.read_text(encoding='utf-8'))

    def test_local_remember_me_explains_its_behavior_and_warning_at_the_property(self):
        resume = next(
            call for call in properties('reference/authorization/local.md')
            if ast.literal_eval(call.args[0]) == 'rememberMe'
        )
        default = next(keyword.value for keyword in resume.keywords if keyword.arg == 'default')
        self.assertEqual('forbidden', ast.literal_eval(default))
        text = (DOCS / 'reference/authorization/local.md').read_text(encoding='utf-8')
        self.assertNotIn('pamAccountResumeAllowed', text)
        self.assertNotIn('!!! warning', text.split('## Properties', 1)[0])
        self.assertNotRegex(text, r'(?m)^## RememberMe\s*$')
        section = text.split('<<property("rememberMe",', 1)[1].split('<<property("remoteName",', 1)[0]
        self.assertIn('!!! warning', section)
        self.assertIn('UID/SID', section)
        self.assertIn('`auth` is not repeated', section)
        row = next(line for line in text.splitlines() if line.startswith('| [RememberMe with PAM]'))
        self.assertIn('compatibility_editions(False,True,"linux")', row)
        self.assertIn('compatibility_editions(False,None,"darwin")', row)
        self.assertIn('compatibility_editions(False,None,"windows")', row)

    def test_keepalive_combines_the_shared_enforceable_and_duration_types(self):
        keepalive = next(
            call for call in properties('reference/flow.md')
            if ast.literal_eval(call.args[0]) == 'keepAlive'
        )
        enforceable = keepalive.args[1]
        self.assertIsInstance(enforceable, ast.Call)
        self.assertEqual('ref', enforceable.func.id)
        self.assertEqual('Enforceable', ast.literal_eval(enforceable.args[0]))
        self.assertEqual('data-type.md#enforceable', ast.literal_eval(enforceable.args[1]))
        duration = enforceable.args[2]
        self.assertIsInstance(duration, ast.Call)
        self.assertEqual('ref', duration.func.id)
        self.assertEqual('Duration', ast.literal_eval(duration.args[0]))
        self.assertEqual('data-type.md#duration', ast.literal_eval(duration.args[1]))

    def test_acme_directory_uses_the_shared_url_type(self):
        directory = next(
            call for call in properties('reference/transports/tls/index.md')
            if ast.literal_eval(call.args[0]) == 'directoryUrl'
        )
        self.assertEqual('URL', ast.literal_eval(directory.args[1]))
        self.assertEqual('../../data-type.md#url', ast.literal_eval(directory.args[2]))

    def test_empty_flow_regex_defaults_are_not_quoted_twice(self):
        regexes = [
            call for call in properties('reference/flow.md')
            if isinstance(call.args[1], ast.Constant)
            and ast.literal_eval(call.args[1]) == 'Regex'
        ]
        self.assertTrue(regexes)
        for call in regexes:
            with self.subTest(property=ast.literal_eval(call.args[0])):
                default = next(keyword.value for keyword in call.keywords if keyword.arg == 'default')
                self.assertEqual('', ast.literal_eval(default))
