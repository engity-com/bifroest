from pathlib import Path
import re
import shlex
from unittest import TestCase

import yaml


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
PAGE = DOCS / 'setup/github-actions.md'


def workflows():
    blocks = re.findall(r'```yaml title="\.github/workflows/bifroest.yml"\n(.*?)\n```', PAGE.read_text(), re.DOTALL)
    return [yaml.load(block, Loader=yaml.BaseLoader) for block in blocks]


class GitHubActionsDocumentationTest(TestCase):
    def test_action_has_one_installation_navigation_entry(self):
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

        page = 'setup/github-actions.md'
        self.assertEqual(list(destinations(config['nav'])).count(page), 1)
        getting_started = next(item['Getting started'] for item in config['nav'] if 'Getting started' in item)
        installation = next(item['Installation'] for item in getting_started if isinstance(item, dict) and 'Installation' in item)
        self.assertIn(page, destinations(installation))

    def test_setup_overview_groups_all_installation_choices(self):
        overview = (DOCS / 'setup/index.md').read_text()
        installation = re.search(r'^## Installation\n(.*?)(?=^## |\Z)', overview, re.MULTILINE | re.DOTALL).group(1)
        choices = re.findall(r'^\d+\. \[[^\]]+\]\(([^)]+)\)', installation, re.MULTILINE)
        self.assertEqual(choices, ['on-host.md', 'in-docker.md', 'in-kubernetes.md', 'github-actions.md'])

    def test_entry_points_link_to_the_action_page(self):
        for name in ('index.md', 'setup/index.md', 'setup/distribution.md', 'guides/index.md', 'guides/testing.md'):
            page = DOCS / name
            targets = re.findall(r'\]\(([^)]+)\)', page.read_text())
            with self.subTest(page=name):
                self.assertTrue(any((page.parent / target.split('#', 1)[0]).resolve() == PAGE for target in targets))

    def test_local_links_resolve(self):
        for target in re.findall(r'\]\(([^)]+)\)', PAGE.read_text()):
            if '://' in target or target.startswith('#'):
                continue
            with self.subTest(target=target):
                self.assertTrue((PAGE.parent / target.split('#', 1)[0]).is_file())

    def test_workflows_install_before_running_commands_with_read_only_permissions(self):
        examples = workflows()
        self.assertEqual(len(examples), 1)
        for workflow in examples:
            with self.subTest(workflow=workflow['name']):
                self.assertEqual(workflow['on'], ['push', 'pull_request'])
                self.assertEqual(workflow['permissions'], {'contents': 'read'})
                self.assertEqual(len(workflow['jobs']), 1)
                job = next(iter(workflow['jobs'].values()))
                self.assertEqual(job['runs-on'], 'ubuntu-24.04')
                steps = job['steps']
                setup = next(i for i, step in enumerate(steps) if step.get('uses') == 'engity-com/bifroest-action@v1')
                for index, step in enumerate(steps):
                    if 'run' in step:
                        self.assertGreater(index, setup)
                        self.assertEqual(shlex.split(step['run'])[0], 'bifroest')

    def test_test_workflow_checks_out_inputs_and_preserves_failure_status(self):
        workflow = workflows()[0]
        steps = workflow['jobs']['configuration']['steps']
        self.assertEqual(steps[0]['uses'], 'actions/checkout@v7')
        self.assertEqual(steps[0]['with']['persist-credentials'], 'false')
        self.assertNotIn('version', steps[1].get('with', {}))
        command = shlex.split(steps[2]['run'])
        self.assertEqual(command, ['bifroest', 'test', '-c', 'configuration.yaml', '.'])
        self.assertNotIn('continue-on-error', steps[2])
        self.assertNotIn('continue-on-error', workflow['jobs']['configuration'])

    def test_action_details_link_to_upstream_documentation(self):
        self.assertIn('https://github.com/engity-com/bifroest-action#readme', PAGE.read_text())
