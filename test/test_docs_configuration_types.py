import ast
import re
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
        tls = config['http']['tls']
        self.assertNotIn('certificates', tls)
        self.assertTrue(tls['acme']['enabled'])
        self.assertTrue(tls['acme']['acceptTerms'])
        self.assertEqual([':443'], config['http']['addresses'])

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
        self.assertEqual(1, len(introduction.strip().splitlines()))
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

    def test_pam_browser_resume_documents_opt_in_and_platform_support(self):
        resume = next(
            call for call in properties('reference/authorization/local.md')
            if ast.literal_eval(call.args[0]) == 'pamAccountResumeAllowed'
        )
        default = next(keyword.value for keyword in resume.keywords if keyword.arg == 'default')
        self.assertIs(False, ast.literal_eval(default))
        text = (DOCS / 'reference/authorization/local.md').read_text(encoding='utf-8')
        row = next(line for line in text.splitlines() if line.startswith('| [PAM RememberMe]'))
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
            call for call in properties('reference/connection/http/index.md')
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
