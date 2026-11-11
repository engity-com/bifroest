import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
assert.equal(
  process.platform,
  'linux',
  'the PAM integration harness requires a native Linux container host',
);
const runtime = process.env.BIFROEST_E2E_RUNTIME ?? 'podman';
assert(
  ['podman', 'docker'].includes(runtime),
  'select an explicit owned container runtime, never an external cluster',
);
const matrix = readFileSync(path.join(root, 'cmd/build/build-matrix.go'), 'utf8');
const image =
  process.arch === 'x64'
    ? matrix.match(/const binaryLinuxAmd64Image = "([^"]+)"/)?.[1]
    : process.arch === 'arm64'
      ? matrix.match(/sys\.ArchArm64:\s*"([^"]+)"/)?.[1]
      : null;
assert(
  image?.includes('@sha256:'),
  'use the repository-managed native build image, not another dependency pin',
);
function command(name, args, options = {}) {
  const result = spawnSync(name, args, {
    cwd: root,
    encoding: 'utf8',
    timeout: 20 * 60_000,
    maxBuffer: 64 << 20,
    ...options,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${name} failed: ${result.error?.message ?? result.status}\n${result.stdout ?? ''}\n${result.stderr ?? ''}`,
    );
  }
  return result.stdout;
}
const go = JSON.parse(command('go', ['env', '-json', 'GOROOT', 'GOMODCACHE']));
const require = createRequire(new URL('../../web/package.json', import.meta.url));
const { chromium } = require('playwright');
const browsers = path.dirname(path.dirname(path.dirname(chromium.executablePath())));
const output = path.join(root, 'var/e2e');
const cache = path.join(root, 'var/pam-integration/go-cache');
mkdirSync(output, { recursive: true });
mkdirSync(cache, { recursive: true });
const owned = `bifroest-pam-${process.pid}-${Date.now()}`;
const tag = `localhost/${owned}:test`;
const required = [
  'TestLinuxPamRememberMeActualHttpsNativePolicyAndRestart',
  'TestLinuxPamRememberMeDefaultOptOutRejectsEnrollment',
  'TestBrowserLocalPamPasswordRememberMeUiAcrossProfileRestart',
  'TestBrowserLocalPamInteractiveRememberMeUiAcrossProfileRestart',
];
const count = Number(process.env.BIFROEST_TEST_PAM_COUNT ?? '1');
assert(
  Number.isInteger(count) && count >= 1 && count <= 10,
  'PAM test repetitions must be between 1 and 10',
);
const race = process.env.BIFROEST_TEST_PAM_RACE === '1' ? ['-race'] : [];
try {
  command(
    runtime,
    [
      'build',
      '--build-arg',
      `BASE_IMAGE=${image}`,
      '--tag',
      tag,
      '--file',
      path.join(root, 'test/pam/Containerfile'),
      path.join(root, 'test/pam'),
    ],
    { stdio: 'inherit' },
  );
  const result = spawnSync(
    runtime,
    [
      'run',
      '--rm',
      '--name',
      owned,
      '--network=none',
      '--security-opt=no-new-privileges',
      '--security-opt=label=disable',
      '--volume',
      `${root}:/src:ro`,
      '--volume',
      `${realpathSync(go.GOROOT)}:/mise-go:ro`,
      '--volume',
      `${realpathSync(go.GOMODCACHE)}:/modules:ro`,
      '--volume',
      `${cache}:/go-cache:rw`,
      '--volume',
      `${realpathSync(process.execPath)}:/mise-node:ro`,
      '--volume',
      `${browsers}:/browsers:ro`,
      '--workdir',
      '/src/pkg/service',
      '--env',
      'GOROOT=/mise-go',
      '--env',
      'GOMODCACHE=/modules',
      '--env',
      'GOCACHE=/go-cache',
      '--env',
      'GOPROXY=off',
      '--env',
      'GOSUMDB=off',
      '--env',
      'GOFLAGS=-p=2',
      '--env',
      'CGO_ENABLED=1',
      '--env',
      'GOTMPDIR=/tmp/opencode',
      '--env',
      'TMPDIR=/tmp/opencode',
      '--env',
      'TZ=UTC',
      '--env',
      'BIFROEST_TEST_PAM_IN_CONTAINER=1',
      '--env',
      'BIFROEST_TEST_BROWSER_UI=1',
      '--env',
      'BIFROEST_TEST_NODE=/mise-node',
      '--env',
      'PLAYWRIGHT_BROWSERS_PATH=/browsers',
      tag,
      '/mise-go/bin/go',
      'test',
      '-json',
      ...race,
      `-count=${count}`,
      '-timeout=10m',
      '-run',
      `^(${required.join('|')})$`,
      '.',
    ],
    { cwd: root, encoding: 'utf8', timeout: 15 * 60_000, maxBuffer: 64 << 20 },
  );
  writeFileSync(path.join(output, 'pam-browser.json'), result.stdout ?? '');
  writeFileSync(path.join(output, 'pam-browser.stderr.log'), result.stderr ?? '');
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  assert(
    !result.error && result.status === 0,
    `native PAM container failed: ${result.error?.message ?? result.status}`,
  );
  const events = result.stdout
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line));
  assert(
    !events.some((event) => ['skip', 'fail', 'build-fail'].includes(event.Action)),
    'native PAM coverage must not be skipped',
  );
  for (const name of required) {
    assert.equal(
      events.filter((event) => event.Test === name && event.Action === 'pass').length,
      count,
      `missing successful native test: ${name}`,
    );
  }
} finally {
  spawnSync(runtime, ['container', 'rm', '--force', owned], { encoding: 'utf8', timeout: 30_000 });
  spawnSync(runtime, ['image', 'rm', tag], { encoding: 'utf8', timeout: 30_000 });
}
