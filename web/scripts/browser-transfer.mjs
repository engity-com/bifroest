import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserGoToolchain } from './browser-key.mjs';

// Reviewed against MISE go-licenses 2.0.1 report/save for this exact js/wasm
// entry. These are module license texts, not complete release source provenance.
const approved = new Map([
  [
    'github.com/fxamacker/cbor/v2@v2.9.6',
    '78cad457d5ea7318230f3d969d4cdf29cef45524a1fc8ca3a97646da1ad7a841',
  ],
  [
    'github.com/x448/float16@v0.8.4',
    'a555f1194fdac34da70fb416968f7e2217b02352c26c1eac2fa45fcb4290ae8d',
  ],
]);

export function buildBrowserTransfer(output) {
  const { cwd, go, version, runtimeHash, runtimeSource } = browserGoToolchain(output);
  const target = new URL('browser-transfer.wasm', output);
  go([
    'build',
    '-trimpath',
    '-ldflags=-s -w',
    '-o',
    fileURLToPath(target),
    './cmd/browser-transfer',
  ]);
  if (statSync(target).size > 8 << 20) {
    throw new Error('Browser transfer WASM exceeds the unchanged public asset limit');
  }
  const entries = new Map();
  for (const line of go([
    'list',
    '-deps',
    '-f',
    '{{with .Module}}{{.Path}}@{{.Version}}\t{{.Dir}}\t{{if .Replace}}replaced{{end}}{{end}}',
    './cmd/browser-transfer',
  ]).split('\n')) {
    if (!line || line.startsWith('github.com/engity-com/bifroest@\t')) {
      continue;
    }
    const fields = line.split('\t');
    const [name, directory, replaced] = fields;
    if (fields.length !== 3 || !approved.has(name) || replaced !== '') {
      throw new Error('Unreviewed or replaced browser transfer Go module');
    }
    const text = readFileSync(join(directory, 'LICENSE'));
    const hash = createHash('sha256').update(text).digest('hex');
    if (hash !== approved.get(name)) {
      throw new Error('Browser transfer Go module license hash mismatch');
    }
    entries.set(name, {
      module: name,
      license: 'MIT',
      licenseSHA256: hash,
      text: text.toString('utf8'),
    });
  }
  if (entries.size !== approved.size) {
    throw new Error('Browser transfer Go module inventory changed');
  }
  const modules = [...entries.values()].sort((left, right) =>
    left.module.localeCompare(right.module, 'en-US'),
  );
  const project = readFileSync(join(cwd, 'LICENSES/Apache-2.0.txt'), 'utf8');
  const standard = readFileSync(
    join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.3.txt'),
    'utf8',
  );
  const notices = [
    `Bifröst browser artifact transport bridge: Apache-2.0\n${project}`,
    `${version} runtime and standard library: BSD-3-Clause\n${standard}`,
    ...modules.map((entry) => `${entry.module}: MIT\n${entry.text}`),
  ].join('\n\n');
  writeFileSync(new URL('browser-transfer-licenses.txt', output), notices);
  appendFileSync(
    new URL('third-party-licenses.txt', output),
    `\n\nGo/WASM artifact transport notices\n\n${notices}`,
  );
  writeFileSync(
    new URL('browser-transfer-components.json', output),
    `${JSON.stringify(
      {
        schema: 'bifroest-browser-transfer-components-v1',
        toolchain: version,
        runtimeSHA256: runtimeHash,
        runtimeSource,
        modules: modules.map(({ text: _text, ...entry }) => entry),
        project: { module: 'github.com/engity-com/bifroest', license: 'Apache-2.0' },
        wasmSHA256: createHash('sha256').update(readFileSync(target)).digest('hex'),
      },
      null,
      2,
    )}\n`,
  );
}
