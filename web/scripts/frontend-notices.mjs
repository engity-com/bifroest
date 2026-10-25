import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'jsonc-parser';

const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const version = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function productionDependencies(root) {
  const errors = [];
  const lock = parse(readFileSync(join(root, 'bun.lock'), 'utf8'), errors, {
    allowTrailingComma: true,
  });
  if (
    errors.length !== 0 ||
    lock?.lockfileVersion !== 2 ||
    ![0, 1].includes(lock.configVersion) ||
    Object.keys(lock.workspaces ?? {}).join() !== '' ||
    lock.workspaces?.[''] === undefined ||
    lock.packages === null ||
    typeof lock.packages !== 'object' ||
    Array.isArray(lock.packages)
  ) {
    throw new Error('Unsupported or malformed Bun lockfile');
  }
  // Never guess nested/isolated, alias, workspace, Git or file resolutions.
  // Review this adapter when adding such dependencies or changing Bun's format.
  if (Object.keys(lock.packages).some((name) => !packageName.test(name))) {
    throw new Error('Frontend inventory requires a flat, hoisted Bun dependency tree');
  }
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const direct = manifest.dependencies ?? {};
  const pinned = lock.workspaces[''].dependencies ?? {};
  if (
    Object.keys(direct).length !== Object.keys(pinned).length ||
    Object.entries(direct).some(([name, range]) => pinned[name] !== range)
  ) {
    throw new Error('Frontend manifest and Bun lockfile dependencies differ');
  }
  const selected = new Map();
  function visit(name, optional = false) {
    if (!packageName.test(name)) {
      throw new Error(`Unsupported frontend dependency name: ${name}`);
    }
    if (selected.has(name)) {
      return;
    }
    const directory = join(root, 'node_modules', name);
    if (optional && !existsSync(join(directory, 'package.json'))) {
      return;
    }
    const entry = lock.packages[name];
    const metadata = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
    const integrity = entry?.[3];
    if (
      !Array.isArray(entry) ||
      entry.length !== 4 ||
      entry[2] === null ||
      typeof entry[2] !== 'object' ||
      Array.isArray(entry[2]) ||
      entry[0] !== `${name}@${metadata.version}` ||
      typeof metadata.version !== 'string' ||
      !version.test(metadata.version) ||
      metadata.name !== name ||
      typeof metadata.license !== 'string' ||
      typeof integrity !== 'string' ||
      !/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity)
    ) {
      throw new Error(`Frontend dependency/lock/license metadata is inconsistent: ${name}`);
    }
    selected.set(name, { directory, metadata, integrity });
    const details = entry[2];
    const optionalPeers = new Set(details.optionalPeers ?? []);
    for (const child of Object.keys(details.dependencies ?? {})) {
      visit(child);
    }
    for (const child of Object.keys(details.peerDependencies ?? {})) {
      visit(child, optionalPeers.has(child));
    }
    for (const child of Object.keys(details.optionalDependencies ?? {})) {
      visit(child, true);
    }
  }
  for (const name of Object.keys(direct)) {
    visit(name);
  }
  return [...selected].sort(([left], [right]) => left.localeCompare(right, 'en-US'));
}

// Conservative production dependency inventory (not a claim about exact
// tree-shaken module usage). Never include compiler/browser-test dependencies.
export function writeFrontendNotices(
  output,
  root = fileURLToPath(new URL('../', import.meta.url)),
) {
  const supplements = JSON.parse(readFileSync(join(root, 'licenses/supplements.json'), 'utf8'));
  const components = [];
  const sections = [];
  for (const [, { directory, metadata, integrity }] of productionDependencies(root)) {
    const files = readdirSync(directory)
      .filter((name) => /^(?:licen[sc]e|copying)(?:$|[._-])/i.test(name))
      .sort();
    let source = 'npm archive';
    let text;
    if (files.length === 0) {
      const supplement = supplements[`${metadata.name}@${metadata.version}`];
      if (supplement === undefined || supplement.license !== metadata.license) {
        throw new Error(`Frontend dependency license text missing: ${metadata.name}`);
      }
      const bytes = readFileSync(join(root, 'licenses', supplement.file));
      if (createHash('sha256').update(bytes).digest('hex') !== supplement.sha256) {
        throw new Error('Frontend license supplement hash mismatch');
      }
      source = supplement.source;
      text = `${supplement.note}\n${bytes.toString('utf8')}`;
    } else {
      text = files
        .map((name) => `${name}\n${readFileSync(join(directory, name), 'utf8')}`)
        .join('\n');
    }
    sections.push(
      `${metadata.name}@${metadata.version}\nLicense: ${metadata.license}\nLicense text source: ${source}\n${text}`,
    );
    components.push({
      name: metadata.name,
      version: metadata.version,
      license: metadata.license,
      integrity,
      licenseTextSource: source,
    });
  }
  writeFileSync(
    new URL('third-party-licenses.txt', output),
    `Browser UI production dependency notices\n\n${sections.join('\n\n====================\n\n')}`,
  );
  writeFileSync(
    new URL('frontend-components.json', output),
    `${JSON.stringify(
      {
        schema: 'bifroest-frontend-components-v1',
        components,
        localBundlingPatches: [
          {
            component: '@xterm/xterm@6.0.0',
            description:
              'Parenthesize documentOverride fallback in CoreBrowserService initialization; see web/scripts/README.md.',
          },
        ],
      },
      null,
      2,
    )}\n`,
  );
}
