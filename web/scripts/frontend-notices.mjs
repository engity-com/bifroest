import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// Conservative production dependency inventory (not a claim about exact
// tree-shaken module usage). Never include compiler/browser-test dependencies.
export function writeFrontendNotices(output) {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  const supplements = JSON.parse(readFileSync(join(root, 'licenses/supplements.json'), 'utf8'));
  const components = [], sections = [];
  for (const [path, entry] of Object.entries(lock.packages).sort(([left], [right]) => left.localeCompare(right, 'en-US'))) {
    if (!path.startsWith('node_modules/') || entry.dev === true || entry.optional === true) continue;
    const directory = join(root, path);
    const metadata = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
    if (metadata.version !== entry.version || typeof metadata.license !== 'string') throw new Error('Frontend dependency/license metadata is inconsistent');
    const files = readdirSync(directory).filter(name => /^(?:licen[sc]e|copying)(?:$|[._-])/i.test(name)).sort();
    let source = 'npm archive', text;
    if (files.length === 0) {
      const supplement = supplements[`${metadata.name}@${metadata.version}`];
      if (supplement === undefined || supplement.license !== metadata.license) throw new Error(`Frontend dependency license text missing: ${metadata.name}`);
      const bytes = readFileSync(join(root, 'licenses', supplement.file));
      if (createHash('sha256').update(bytes).digest('hex') !== supplement.sha256) throw new Error('Frontend license supplement hash mismatch');
      source = supplement.source;
      text = `${supplement.note}\n${bytes.toString('utf8')}`;
    } else text = files.map(name => `${name}\n${readFileSync(join(directory, name), 'utf8')}`).join('\n');
    sections.push(`${metadata.name}@${metadata.version}\nLicense: ${metadata.license}\nLicense text source: ${source}\n${text}`);
    components.push({ name: metadata.name, version: metadata.version, license: metadata.license, integrity: entry.integrity ?? null, licenseTextSource: source });
  }
  writeFileSync(new URL('third-party-licenses.txt', output), 'Browser UI production dependency notices\n\n' + sections.join('\n\n====================\n\n'));
  writeFileSync(new URL('frontend-components.json', output), JSON.stringify({ schema: 'bifroest-frontend-components-v1', components,
    localBundlingPatches: [{ component: '@xterm/xterm@6.0.0', description: 'Parenthesize documentOverride fallback in CoreBrowserService initialization; see web/scripts/README.md.' }],
  }, null, 2) + '\n');
}
