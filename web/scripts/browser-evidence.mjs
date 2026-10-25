import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { browserGoToolchain } from './browser-key.mjs';

// Reviewed MISE go-licenses 2.0.1 report/save for cmd/browser-evidence. This is
// conservative module-level notice inventory, not release-wide source proof.
const approved = new Map([
  [
    'filippo.io/age@v1.3.2',
    [
      'BSD-3-Clause',
      [['LICENSE', 'c5d65279d02955c0fc2294ae417c3add650d228f4f5c82bd6d531fc26c89cd96']],
    ],
  ],
  [
    'filippo.io/edwards25519@v1.2.0',
    [
      'BSD-3-Clause',
      [['LICENSE', '2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067']],
    ],
  ],
  [
    'filippo.io/hpke@v0.4.0',
    [
      'BSD-3-Clause',
      [['LICENSE', '911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad']],
    ],
  ],
  [
    'github.com/fxamacker/cbor/v2@v2.9.6',
    ['MIT', [['LICENSE', '78cad457d5ea7318230f3d969d4cdf29cef45524a1fc8ca3a97646da1ad7a841']]],
  ],
  [
    'github.com/google/uuid@v1.6.0',
    [
      'BSD-3-Clause',
      [['LICENSE', '0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d']],
    ],
  ],
  [
    'github.com/klauspost/compress@v1.20.3',
    [
      'Apache-2.0 AND BSD-3-Clause AND MIT',
      [
        ['LICENSE', '0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf'],
        [
          'internal/snapref/LICENSE',
          'f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf',
        ],
        [
          'zstd/internal/xxhash/LICENSE.txt',
          'f566a9f97bacdaf00d9f21dd991e81dc11201c4e016c86b470799429a1c9a79c',
        ],
      ],
    ],
  ],
  [
    'github.com/mikesmitty/edkey@v0.0.0-20170222072505-3356ea4e686a',
    ['MIT', [['LICENSE', 'bc3d8d6e17573cf58014ee2da6aa37ad62fe785f326b3ede94675a0e44090539']]],
  ],
  [
    'github.com/vmihailenco/msgpack/v5@v5.4.1',
    [
      'BSD-2-Clause',
      [['LICENSE', '1530185dd39cdde7cb2f786a7a5fcf8bc34368b6ae73c15e72bafe88fd80b9a2']],
    ],
  ],
  [
    'github.com/vmihailenco/tagparser/v2@v2.0.0',
    [
      'BSD-2-Clause',
      [['LICENSE', '0f02aac22084ef463aa5f42f566feeec6aa4c99653519744a8c25cb079da5b5d']],
    ],
  ],
  [
    'github.com/x448/float16@v0.8.4',
    ['MIT', [['LICENSE', 'a555f1194fdac34da70fb416968f7e2217b02352c26c1eac2fa45fcb4290ae8d']]],
  ],
  [
    'golang.org/x/crypto@v0.58.0',
    [
      'BSD-3-Clause',
      [['LICENSE', '911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad']],
    ],
  ],
]);

export function buildBrowserEvidence(output) {
  const { cwd, go, version, runtimeHash, runtimeSource } = browserGoToolchain(output);
  const directory = join(cwd, 'var', 'webui-evidence-build');
  mkdirSync(directory, { recursive: true });
  const target = join(directory, 'browser-evidence.wasm');
  go(['build', '-trimpath', '-ldflags=-s -w', '-o', target, './cmd/browser-evidence']);
  const raw = readFileSync(target);
  if (raw.length > 24 << 20) {
    throw new Error('Browser evidence WASM exceeds its uncompressed worker bound');
  }
  const compressed = gzipSync(raw, { level: 9 });
  if (compressed.length > 8 << 20) {
    throw new Error('Compressed browser evidence exceeds the unchanged asset bound');
  }
  writeFileSync(new URL('browser-evidence.wasm.gz', output), compressed);
  const modules = new Map();
  for (const line of go([
    'list',
    '-deps',
    '-f',
    '{{with .Module}}{{.Path}}@{{.Version}}\t{{.Dir}}\t{{if .Replace}}replaced{{end}}{{end}}',
    './cmd/browser-evidence',
  ]).split('\n')) {
    if (!line || line.startsWith('github.com/engity-com/bifroest@\t')) {
      continue;
    }
    const fields = line.split('\t');
    const [module, root, replacement] = fields;
    const expected = approved.get(module);
    if (fields.length !== 3 || expected === undefined || replacement !== '') {
      throw new Error('Unreviewed or replaced browser evidence module');
    }
    const [license, files] = expected;
    const texts = files.map(([path, hash]) => {
      const bytes = readFileSync(join(root, path));
      if (createHash('sha256').update(bytes).digest('hex') !== hash) {
        throw new Error('Browser evidence module license changed');
      }
      return { path, sha256: hash, text: bytes.toString('utf8') };
    });
    modules.set(module, { module, license, files: texts });
  }
  if (modules.size !== approved.size) {
    throw new Error('Browser evidence module inventory changed');
  }
  const entries = [...modules.values()].sort((left, right) =>
    left.module.localeCompare(right.module, 'en-US'),
  );
  const notices = [
    `Bifröst client-only evidence bridge/core: Apache-2.0\n${readFileSync(join(cwd, 'LICENSES/Apache-2.0.txt'), 'utf8')}`,
    `${version} runtime/standard library: BSD-3-Clause\n${readFileSync(join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.3.txt'), 'utf8')}`,
    ...entries.map(
      (entry) =>
        `${entry.module}\nLicenses: ${entry.license}\n${entry.files.map((file) => `${file.path}\n${file.text}`).join('\n\n')}`,
    ),
  ].join('\n\n');
  writeFileSync(new URL('browser-evidence-licenses.txt', output), notices);
  appendFileSync(
    new URL('third-party-licenses.txt', output),
    `\n\nGo/WASM client evidence notices\n\n${notices}`,
  );
  writeFileSync(
    new URL('browser-evidence-components.json', output),
    `${JSON.stringify(
      {
        schema: 'bifroest-browser-evidence-components-v1',
        toolchain: version,
        runtimeSHA256: runtimeHash,
        runtimeSource,
        compression: 'gzip',
        rawBytes: raw.length,
        compressedBytes: compressed.length,
        wasmSHA256: createHash('sha256').update(raw).digest('hex'),
        compressedSHA256: createHash('sha256').update(compressed).digest('hex'),
        modules: entries.map((entry) => ({
          ...entry,
          files: entry.files.map(({ text: _text, ...file }) => file),
        })),
        project: { module: 'github.com/engity-com/bifroest', license: 'Apache-2.0' },
      },
      null,
      2,
    )}\n`,
  );
}
