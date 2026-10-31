import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const manifestName = 'browser-build.json';

function files(root, directory = root) {
  const result = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const info = lstatSync(path);
    if (info.isSymbolicLink()) {
      throw new Error('Browser build inputs cannot contain symlinks');
    }
    if (info.isDirectory()) {
      result.push(...files(root, path));
    } else if (info.isFile() && info.nlink === 1) {
      result.push(relative(root, path).replaceAll('\\', '/'));
    } else {
      throw new Error('Browser build inputs must be regular single-link files');
    }
  }
  return result.sort();
}

function fingerprint(root, name) {
  const bytes = readFileSync(join(root, name));
  return { name, bytes: bytes.length, sha256: sha256(bytes) };
}

function coordinates(module) {
  const at = module.lastIndexOf('@');
  if (at < 1) {
    throw new Error('Browser Go module lacks exact version');
  }
  return { name: module.slice(0, at), version: module.slice(at + 1) };
}

// Bound only reviewed build outputs and conservative component inventories.
// This manifest is build metadata, not a signed/source-equivalence attestation.
export function writeBrowserRelease(
  output,
  root = fileURLToPath(new URL('../../', import.meta.url)),
  snapshot,
) {
  const target = fileURLToPath(output);
  const assets = files(target)
    .filter((name) => name !== manifestName)
    .map((name) => fingerprint(target, name));
  if (
    assets.length > 2048 ||
    assets.some((asset) => asset.bytes > 8 << 20) ||
    assets.reduce((total, asset) => total + asset.bytes, 0) > 64 << 20
  ) {
    throw new Error('Browser release inventory exceeds its fixed resource bounds');
  }
  for (const name of [
    'index.html',
    'go-wasm-exec.js',
    'browser-key-worker.js',
    'browser-transfer-worker.js',
    'browser-evidence-worker.js',
    'third-party-licenses.txt',
    'frontend-components.json',
    'browser-key-components.json',
    'browser-transfer-components.json',
    'browser-evidence-components.json',
  ]) {
    if (!assets.some((asset) => asset.name === name)) {
      throw new Error('Browser release output is incomplete');
    }
  }
  const json = (name) => JSON.parse(readFileSync(join(target, name), 'utf8'));
  const frontend = json('frontend-components.json');
  const key = json('browser-key-components.json');
  const transfer = json('browser-transfer-components.json');
  const evidence = json('browser-evidence-components.json');
  if (
    frontend.schema !== 'bifroest-frontend-components-v1' ||
    key.schema !== 'bifroest-browser-key-components-v1' ||
    transfer.schema !== 'bifroest-browser-transfer-components-v1' ||
    evidence.schema !== 'bifroest-browser-evidence-components-v1'
  ) {
    throw new Error('Browser component schema changed');
  }
  const runtime = sha256(readFileSync(join(target, 'go-wasm-exec.js')));
  for (const component of [key, transfer, evidence]) {
    if (
      component.toolchain !== 'go1.27.3' ||
      component.runtimeSHA256 !== runtime ||
      component.runtimeSource !== 'MISE-selected GOROOT/lib/wasm/wasm_exec.js'
    ) {
      throw new Error('Release browser assets require the pinned normal GOROOT runtime');
    }
  }
  if (
    sha256(readFileSync(join(target, 'browser-key.wasm'))) !== key.wasmSHA256 ||
    sha256(readFileSync(join(target, 'browser-transfer.wasm'))) !== transfer.wasmSHA256
  ) {
    throw new Error('Browser WASM inventory digest mismatch');
  }
  const compressed = readFileSync(join(target, 'browser-evidence.wasm.gz'));
  const raw = gunzipSync(compressed, { maxOutputLength: 24 << 20 });
  if (
    evidence.compression !== 'gzip' ||
    compressed.length !== evidence.compressedBytes ||
    raw.length !== evidence.rawBytes ||
    sha256(compressed) !== evidence.compressedSHA256 ||
    sha256(raw) !== evidence.wasmSHA256
  ) {
    throw new Error('Compressed browser WASM inventory mismatch');
  }
  const components = frontend.components.map((component) => ({
    ecosystem: 'npm',
    name: component.name,
    version: component.version,
    license: component.license,
    integrity: component.integrity,
    licenseTextSource: component.licenseTextSource,
    artifacts: ['browser-ui'],
  }));
  const modules = new Map();
  function add(module, license, artifact) {
    const value = modules.get(module);
    if (value !== undefined) {
      if (value.license !== license) {
        throw new Error('Browser Go license inventories disagree');
      }
      if (!value.artifacts.includes(artifact)) {
        value.artifacts.push(artifact);
      }
    } else {
      modules.set(module, {
        ecosystem: 'golang',
        ...coordinates(module),
        license,
        integrity: '',
        licenseTextSource: 'reviewed Go/WASM component notices',
        artifacts: [artifact],
      });
    }
  }
  for (const module of key.modules) {
    add(module, key.externalLicense, 'browser-key.wasm');
  }
  for (const module of transfer.modules) {
    add(module.module, module.license, 'browser-transfer.wasm');
  }
  for (const module of evidence.modules) {
    add(module.module, module.license, 'browser-evidence.wasm.gz');
  }
  components.push(...modules.values());
  components.push({
    ecosystem: 'go-runtime',
    name: 'Go runtime and standard library',
    version: '1.27.3',
    license: 'BSD-3-Clause',
    integrity: '',
    licenseTextSource: 'reviewed Go 1.27.3 BSD notice',
    artifacts: [
      'go-wasm-exec.js',
      'browser-key.wasm',
      'browser-transfer.wasm',
      'browser-evidence.wasm.gz',
    ],
  });
  for (const component of components) {
    component.artifacts.sort();
  }
  components.sort((left, right) =>
    `${left.ecosystem}/${left.name}@${left.version}`.localeCompare(
      `${right.ecosystem}/${right.name}@${right.version}`,
      'en-US',
    ),
  );
  const source = captureBrowserInputs(root);
  if (snapshot !== undefined && JSON.stringify(source) !== JSON.stringify(snapshot)) {
    throw new Error('Browser inputs changed during frontend compilation');
  }
  const manifest = {
    schema: 'bifroest-browser-build-v1',
    scope: 'built-assets-and-conservative-components-not-source-attestation',
    ...source,
    go: key.toolchain,
    assets,
    components,
    localBundlingPatches: frontend.localBundlingPatches,
  };
  const bytes = `${JSON.stringify(manifest, null, 2)}\n`;
  if (Buffer.byteLength(bytes) > 512 << 10) {
    throw new Error('Browser release manifest exceeds metadata bound');
  }
  writeFileSync(join(target, manifestName), bytes);
}

export function captureBrowserInputs(root = fileURLToPath(new URL('../../', import.meta.url))) {
  const inputNames = [
    '.gitattributes',
    'go.mod',
    'go.sum',
    'web/package.json',
    'web/bun.lock',
    'web/bunfig.toml',
    'web/index.html',
    'web/vite.app.config.ts',
    'web/.tool-versions',
  ];
  for (const directory of ['web/src', 'web/scripts', 'web/licenses']) {
    inputNames.push(...files(join(root, directory)).map((name) => `${directory}/${name}`));
  }
  const projectFiles = execFileSync(
    'go',
    [
      'list',
      '-deps',
      '-f',
      '{{if and .Module (eq .Module.Path "github.com/engity-com/bifroest")}}{{$dir := .Dir}}{{range .GoFiles}}{{$dir}}/{{.}}\n{{end}}{{range .EmbedFiles}}{{$dir}}/{{.}}\n{{end}}{{end}}',
      './cmd/browser-key',
      './cmd/browser-transfer',
      './cmd/browser-evidence',
    ],
    {
      cwd: root,
      env: { ...process.env, GOOS: 'js', GOARCH: 'wasm', CGO_ENABLED: '0' },
      encoding: 'utf8',
      maxBuffer: 8 << 20,
    },
  );
  for (const name of projectFiles.split('\n').filter(Boolean)) {
    const path = relative(root, name).replaceAll('\\', '/');
    if (path.startsWith('../') || path.startsWith('/')) {
      throw new Error('Browser project source escapes repository');
    }
    inputNames.push(path);
  }
  const inputs = [...new Set(inputNames)].sort().map((name) => fingerprint(root, name));
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  const dirty =
    execFileSync(
      'git',
      [
        'status',
        '--porcelain',
        '--untracked-files=all',
        '--',
        ...inputs.map((input) => input.name),
      ],
      { cwd: root, encoding: 'utf8' },
    ).trim() !== '';
  const bun = execFileSync('bun', ['--version'], { cwd: root, encoding: 'utf8' }).trim();
  if (bun !== '1.4.4' || process.versions.node !== '26.9.0' || !/^[0-9a-f]{40}$/u.test(revision)) {
    throw new Error('Browser release needs the pinned Bun/Node and source revision');
  }
  return Object.freeze({
    revision,
    dirty,
    bun,
    node: process.versions.node,
    inputs: Object.freeze(inputs.map((input) => Object.freeze(input))),
  });
}
