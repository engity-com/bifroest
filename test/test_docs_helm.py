import re
import textwrap
from pathlib import Path
from unittest import TestCase

import yaml


ROOT = Path(__file__).resolve().parents[1]


class DocsHelmTest(TestCase):
    def test_installation_is_linked_from_navigation_and_existing_topics(self):
        self.assertIn('In Kubernetes with Helm: setup/in-kubernetes.md', (ROOT / 'mkdocs.yml').read_text())
        for page in ['setup/index.md', 'setup/distribution.md', 'setup/operations.md', 'reference/configuration.md', 'reference/environment/kubernetes.md']:
            with self.subTest(page=page):
                self.assertIn('in-kubernetes.md', (ROOT / 'docs' / page).read_text())
        guide = (ROOT / 'docs/setup/in-kubernetes.md').read_text()
        self.assertIn('<<compatibility_matrix(os="linux", packaging="image")>>', guide)
        self.assertNotIn('--version latest', guide)
        self.assertIn('StrictHostKeyChecking=yes', guide)

    def test_prometheus_discovers_each_named_monitoring_port_once(self):
        guide = (ROOT / 'docs/guides/monitoring.md').read_text()
        section = guide.split('### Scrape the Helm deployment\n', 1)[1]
        block = re.search(r'```yaml title="Prometheus scrape job"\n(.*?)```', section, re.DOTALL)
        self.assertIsNotNone(block)
        job = yaml.safe_load(textwrap.dedent(block.group(1)))['scrape_configs'][0]
        self.assertEqual('bifroest', job['job_name'])
        self.assertEqual([{'role': 'pod', 'namespaces': {'names': ['bifroest']}}], job['kubernetes_sd_configs'])
        rules = job['relabel_configs']
        ports = [rule for rule in rules if rule['source_labels'] == ['__meta_kubernetes_pod_container_port_name']]
        self.assertEqual([{'source_labels': ['__meta_kubernetes_pod_container_port_name'], 'action': 'keep', 'regex': 'monitoring'}], ports)
        for annotation, target in [('scheme', '__scheme__'), ('path', '__metrics_path__')]:
            self.assertIn({'source_labels': ['__meta_kubernetes_pod_annotation_prometheus_io_' + annotation], 'target_label': target}, rules)
