import ast
import re
from pathlib import Path
from unittest import TestCase


DOCS = Path(__file__).resolve().parents[1] / 'docs'


def properties(relative):
    text = (DOCS / relative).read_text(encoding='utf-8')
    return [
        ast.parse(f'property({match.group(1)})', mode='eval').body
        for match in re.finditer(r'<<property\((.*?)\)>>', text, re.DOTALL)
    ]


class DocsConfigurationTypesTest(TestCase):
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
