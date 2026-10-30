import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parse } from 'jsonc-parser';
import { writeFrontendNotices } from '../scripts/frontend-notices.mjs';

const integrity = `sha512-${Buffer.alloc(64, 1).toString('base64')}`;

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'bifroest-notices-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const output = join(root, 'output');
  mkdirSync(output);
  mkdirSync(join(root, 'licenses'));
  writeFileSync(join(root, 'licenses/supplements.json'), '{}');
  const manifest = { dependencies: { app: '1.0.0' }, devDependencies: { compiler: '1.0.0' } };
  const lock = {
    lockfileVersion: 2,
    configVersion: 1,
    workspaces: { '': { ...manifest } },
    packages: {},
  };
  function dependency(name, details = {}, chain = [], version = '1.0.0') {
    lock.packages[[...chain, name].join('/')] = [`${name}@${version}`, '', details, integrity];
    const directory = join(root, ...[...chain, name].flatMap((part) => ['node_modules', part]));
    mkdirSync(directory, { recursive: true });
    writeFileSync(
      join(directory, 'package.json'),
      JSON.stringify({ name, version, license: 'MIT' }),
    );
    writeFileSync(join(directory, 'LICENSE'), `License of ${name}`);
  }
  dependency('app');
  dependency('compiler');
  function save() {
    writeFileSync(join(root, 'package.json'), JSON.stringify(manifest));
    // Bun's text lockfile permits comments and trailing commas, not plain JSON.
    writeFileSync(
      join(root, 'bun.lock'),
      `// Bun lockfile\n${JSON.stringify(lock).slice(0, -1)},}`,
    );
  }
  function run() {
    writeFrontendNotices(pathToFileURL(`${output}${sep}`), root);
    return JSON.parse(readFileSync(join(output, 'frontend-components.json'), 'utf8')).components;
  }
  return { root, output, manifest, lock, dependency, save, run };
}

test('Bun notices follow production dependencies and peers, deduplicate cycles and omit dev tools', (t) => {
  const f = fixture(t);
  f.dependency('app', { dependencies: { '@scope/shared': '^1' }, peerDependencies: { peer: '*' } });
  f.dependency('@scope/shared', { dependencies: { app: '^1' } });
  f.dependency('peer');
  f.save();
  const components = f.run();
  assert.deepEqual(components.map((entry) => entry.name).sort(), ['@scope/shared', 'app', 'peer']);
  assert(components.every((entry) => entry.version === '1.0.0' && entry.integrity === integrity));
  assert.match(readFileSync(join(f.output, 'third-party-licenses.txt'), 'utf8'), /License of app/);
});

test('installed optional dependencies/peers are inventoried; absent ones are omitted', (t) => {
  const f = fixture(t);
  f.dependency('app', {
    optionalDependencies: { present: '*', absent: '*' },
    peerDependencies: { peer: '*', missing: '*' },
    optionalPeers: ['peer', 'missing'],
  });
  f.dependency('present');
  f.dependency('peer');
  f.save();
  assert.deepEqual(
    f
      .run()
      .map((entry) => entry.name)
      .sort(),
    ['app', 'peer', 'present'],
  );
});

test('an absent required dependency fails before any notices are published', (t) => {
  const f = fixture(t);
  f.dependency('app', { dependencies: { missing: '*' } });
  f.save();
  assert.throws(f.run, /ENOENT/);
  assert.deepEqual(readdirSync(f.output), []);
});

test('malformed/unsupported lockfiles fail instead of using partial JSONC results', (t) => {
  const f = fixture(t);
  f.save();
  const valid = readFileSync(join(f.root, 'bun.lock'), 'utf8');
  for (const text of [
    valid.slice(0, -1),
    '{}',
    valid.replace('"lockfileVersion":2', '"lockfileVersion":9'),
  ]) {
    writeFileSync(join(f.root, 'bun.lock'), text);
    assert.throws(f.run, /Unsupported or malformed/);
  }
  assert.deepEqual(readdirSync(f.output), []);
});

test('a stale production manifest fails', (t) => {
  const f = fixture(t);
  f.manifest.dependencies = { app: '2.0.0' };
  f.save();
  assert.throws(f.run, /manifest and Bun lockfile/);
});

test('nested versions follow the owning package; scoped chains and cycles stay bounded', (t) => {
  const f = fixture(t);
  f.dependency('app', { dependencies: { '@scope/parent': '*', shared: '*' } });
  f.dependency('shared');
  f.dependency('@scope/parent', { dependencies: { shared: '*' } });
  f.dependency('shared', { dependencies: { app: '*' } }, ['@scope/parent'], '2.0.0');
  f.save();
  assert.deepEqual(
    f
      .run()
      .map((entry) => `${entry.name}@${entry.version}`)
      .sort(),
    ['@scope/parent@1.0.0', 'app@1.0.0', 'shared@1.0.0', 'shared@2.0.0'],
  );
  rmSync(join(f.root, 'node_modules/@scope/parent/node_modules/shared/package.json'));
  assert.throws(
    f.run,
    /ENOENT/,
    'a missing locked nested package must not fall back to another root version',
  );
});

test('dev-only nested resolutions are not shipped or inventoried', (t) => {
  const f = fixture(t);
  f.lock.packages['compiler/nested'] = ['nested@2.0.0', '', {}, integrity];
  f.save();
  assert.deepEqual(
    f.run().map((entry) => entry.name),
    ['app'],
  );
});

test('missing locks, aliases, unsupported sources, invalid integrity and version drift fail', (t) => {
  const f = fixture(t);
  for (const entry of [
    undefined,
    ['other@1.0.0', '', {}, integrity],
    ['app@git:example/repo', '', {}, integrity],
    ['app@2.0.0', '', {}, integrity],
    ['app@1.0.0', '', {}, null],
    ['app@1.0.0', '', {}, 'sha512-short'],
    ['app@1.0.0', '', null, integrity],
  ]) {
    f.lock.packages.app = entry;
    f.save();
    assert.throws(f.run, /metadata is inconsistent/);
  }
  assert.deepEqual(readdirSync(f.output), []);
});

test('a missing license text still blocks the build', (t) => {
  const f = fixture(t);
  rmSync(join(f.root, 'node_modules/app/LICENSE'));
  f.save();
  assert.throws(f.run, /license text missing/);
  assert.deepEqual(readdirSync(f.output), []);
});

test('the historical removed scroll-bar supplement retains its recorded publisher hash', () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const evidence = JSON.parse(
    readFileSync(join(root, 'licenses/react-remove-scroll-bar-2.3.8-evidence.json'), 'utf8'),
  );
  const supplements = JSON.parse(readFileSync(join(root, 'licenses/supplements.json'), 'utf8'));
  const supplement = supplements['react-remove-scroll-bar@2.3.8'];
  const lock = parse(readFileSync(join(root, 'bun.lock'), 'utf8'));
  assert.equal(evidence.component, 'react-remove-scroll-bar@2.3.8');
  assert.equal(evidence.declaredLicense, supplement.license);
  assert.equal(lock.packages['react-remove-scroll-bar'], undefined, 'no longer a UI dependency');
  assert.equal(supplement.source, evidence.licenseSource);
  assert.equal(
    createHash('sha256')
      .update(readFileSync(join(root, 'licenses', supplement.file)))
      .digest('hex'),
    evidence.licenseSha256,
  );
  assert.equal(Object.keys(evidence.identicalPayloadFiles).length, 26);
  for (const [name, digest] of Object.entries(evidence.identicalPayloadFiles)) {
    assert.match(
      name,
      /^(?:README\.md|constants\/package\.json|dist\/(?:es5|es2015|es2019)\/[A-Za-z-]+\.(?:js|d\.ts))$/u,
    );
    assert.match(digest, /^[a-f0-9]{64}$/u);
  }
});
