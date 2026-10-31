import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { captureBrowserInputs, writeBrowserRelease } from '../scripts/browser-release.mjs';

const output = fileURLToPath(new URL('../../pkg/webui/assets/', import.meta.url));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('release inventory binds actual built assets, Go/project inputs and separate npm license provenance', () => {
  const raw = readFileSync(join(output, 'browser-build.json'));
  const manifest = JSON.parse(raw);
  for (const asset of manifest.assets) {
    const bytes = readFileSync(join(output, asset.name));
    assert.equal(bytes.length, asset.bytes);
    assert.equal(hash(bytes), asset.sha256);
  }
  assert(manifest.inputs.some((input) => input.name === 'pkg/recording/cast/verifier.go'));
  assert(manifest.inputs.some((input) => input.name === 'web/bun.lock'));
  assert.equal(
    manifest.components.filter((component) => component.ecosystem === 'go-runtime').length,
    1,
  );
  assert.equal(
    manifest.components.some((component) => component.name === 'react-remove-scroll-bar'),
    false,
  );
  for (const name of ['@mui/material', '@mui/icons-material', '@emotion/react']) {
    const component = manifest.components.find((entry) => entry.name === name);
    assert.equal(component.license, 'MIT');
    assert.equal(component.licenseTextSource, 'npm archive');
    assert.match(component.integrity, /^sha512-/u);
  }
  assert.equal(
    manifest.components.filter((component) => component.name === 'react-is').length,
    2,
    'root and nested production versions have separate notices',
  );
  assert(manifest.scope.includes('not-source-attestation'));
  writeBrowserRelease(pathToFileURL(`${output}/`));
  assert.equal(
    readFileSync(join(output, 'browser-build.json'), 'utf8'),
    raw.toString('utf8'),
    'same inputs produce byte-identical metadata',
  );
});

for (const mode of [
  'missing worker',
  'changed wasm',
  'changed runtime',
  'linked asset',
  'unknown schema',
  'changed input snapshot',
]) {
  test(`release generation refuses ${mode} without publishing a new manifest`, () => {
    const temporary = mkdtempSync(
      join(process.env.TMPDIR || tmpdir(), 'bifroest-browser-inventory-'),
    );
    try {
      cpSync(output, temporary, { recursive: true });
      const before = readFileSync(join(temporary, 'browser-build.json'));
      if (mode === 'missing worker') {
        unlinkSync(join(temporary, 'browser-key-worker.js'));
      }
      if (mode === 'changed wasm') {
        writeFileSync(join(temporary, 'browser-key.wasm'), 'tampered');
      }
      if (mode === 'changed runtime') {
        writeFileSync(join(temporary, 'go-wasm-exec.js'), 'tampered');
      }
      if (mode === 'linked asset') {
        symlinkSync(join(output, 'browser-key.wasm'), join(temporary, 'link.wasm'));
      }
      if (mode === 'unknown schema') {
        const metadata = JSON.parse(readFileSync(join(temporary, 'frontend-components.json')));
        metadata.schema = 'unknown';
        writeFileSync(join(temporary, 'frontend-components.json'), JSON.stringify(metadata));
      }
      const snapshot =
        mode === 'changed input snapshot'
          ? { ...captureBrowserInputs(), revision: 'b'.repeat(40) }
          : undefined;
      assert.throws(() => writeBrowserRelease(pathToFileURL(`${temporary}/`), undefined, snapshot));
      assert.deepEqual(readFileSync(join(temporary, 'browser-build.json')), before);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
}
