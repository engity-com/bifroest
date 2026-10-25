import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, copyFileSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = 'go1.27.3';
const runtimeHash = '0c949f4996f9a89698e4b5c586de32249c3b69b7baadb64d220073cc04acba14';

// Build-only subprocesses. Browser authentication never invokes a Go process.
export function buildBrowserKey(output) {
  const cwd = fileURLToPath(new URL('../../', import.meta.url));
  const env = { ...process.env, GOOS: 'js', GOARCH: 'wasm', CGO_ENABLED: '0' };
  const go = (args) =>
    execFileSync('go', args, { cwd, env, encoding: 'utf8', maxBuffer: 8 << 20 }).trim();
  if (go(['env', 'GOVERSION']) !== version) {
    throw new Error('Browser WASM needs the pinned Go toolchain');
  }
  // Explicit operator-supplied input for restricted development harnesses.
  // Never silently download a runtime or modify the selected toolchain.
  const source =
    process.env.BIFROEST_GO_WASM_EXEC || join(go(['env', 'GOROOT']), 'lib', 'wasm', 'wasm_exec.js');
  const runtime = readFileSync(source);
  if (createHash('sha256').update(runtime).digest('hex') !== runtimeHash) {
    throw new Error('Go WASM runtime version/hash mismatch');
  }
  const target = new URL('browser-key.wasm', output);
  go(['build', '-trimpath', '-ldflags=-s -w', '-o', fileURLToPath(target), './cmd/browser-key']);
  if (statSync(target).size > 8 << 20) {
    throw new Error('Browser key WASM exceeds public asset bound');
  }
  copyFileSync(source, new URL('go-wasm-exec.js', output));
  const modules = [
    ...new Set(
      go([
        'list',
        '-deps',
        '-f',
        '{{with .Module}}{{.Path}}@{{.Version}}{{end}}',
        './cmd/browser-key',
      ])
        .split('\n')
        .filter((value) => value && !value.startsWith('github.com/engity-com/bifroest@')),
    ),
  ];
  const license = readFileSync(
    join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.3.txt'),
    'utf8',
  );
  const approved = new Set(['golang.org/x/crypto@v0.58.0', 'golang.org/x/sys@v0.49.0']);
  if (modules.some((module) => !approved.has(module))) {
    throw new Error('Unreviewed browser WASM module/license');
  }
  writeFileSync(
    new URL('browser-key-components.json', output),
    `${JSON.stringify(
      {
        schema: 'bifroest-browser-key-components-v1',
        toolchain: version,
        runtimeSHA256: runtimeHash,
        runtimeSource: 'pinned toolchain asset (workspace copy during initial development)',
        modules,
        externalLicense: 'BSD-3-Clause',
        project: { module: 'github.com/engity-com/bifroest', license: 'Apache-2.0' },
        wasmSHA256: createHash('sha256').update(readFileSync(target)).digest('hex'),
      },
      null,
      2,
    )}\n`,
  );
  const projectLicense = readFileSync(join(cwd, 'LICENSES/Apache-2.0.txt'), 'utf8');
  const notices = `Bifröst browser key bridge/core: Apache-2.0\n${projectLicense}\n\n${version} runtime and standard library\n${modules.join('\n')}\n\n${license}`;
  writeFileSync(new URL('browser-key-licenses.txt', output), notices);
  appendFileSync(
    new URL('third-party-licenses.txt', output),
    `\n\nGo/WASM browser-key component notices\n\n${notices}`,
  );
}
