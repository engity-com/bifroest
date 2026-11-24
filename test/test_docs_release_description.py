from pathlib import Path
import re
import tomllib
from unittest import TestCase

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ReleaseDescriptionToolsTest(TestCase):
    def test_mise_separates_preview_and_update_and_forwards_arguments(self):
        source = (ROOT / 'mise.toml').read_text()
        for action in ['preview', 'update']:
            with self.subTest(action=action):
                # Other tasks use MISE's multiline inline tables (TOML 1.1).
                section = re.search(r'(?ms)^\[tasks\."release:' + action + r'"\]\n.*?(?=^\[|\Z)', source).group(0)
                config = tomllib.loads(section)
                task = config['tasks']['release:' + action]
                self.assertEqual('go run ./cmd/build release-description ' + action, task['run'])
                self.assertTrue(task['raw_args'])
                self.assertNotIn('depends', task)

    def test_description_update_runs_after_build_and_documentation(self):
        workflow = yaml.load((ROOT / '.github/workflows/release.yml').read_text(), Loader=yaml.BaseLoader)
        job = workflow['jobs']['description']
        self.assertCountEqual(['evaluate', 'build', 'documentation'], job['needs'])
        self.assertEqual({'contents': 'write'}, job['permissions'])
        self.assertNotIn('if', job)
        self.assertEqual('false', job['concurrency']['cancel-in-progress'])
        self.assertIn('needs.evaluate.outputs.release_tag', job['concurrency']['group'])
        checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual('${{ needs.evaluate.outputs.release_tag }}', checkout['with']['ref'])
        update = next(step for step in job['steps'] if 'run' in step)
        self.assertEqual('mise run release:update -- "$RELEASE_TAG"', update['run'])
        self.assertEqual('${{ needs.evaluate.outputs.release_tag }}', update['env']['RELEASE_TAG'])
