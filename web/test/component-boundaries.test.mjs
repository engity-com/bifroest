import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../src/', import.meta.url));
function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}
function imports(path) {
  return [
    ...readFileSync(path, 'utf8').matchAll(
      /^import\s+(type\s+)?([^;]+?)\s+from\s+['"]([^'"]+)['"]/gmu,
    ),
  ].map((match) => {
    const names = match[2].trim();
    const entries = names.startsWith('{')
      ? names
          .slice(1, -1)
          .split(',')
          .map((name) => name.trim())
          .filter(Boolean)
      : [];
    return {
      specifier: match[3],
      typeOnly:
        Boolean(match[1]) ||
        (entries.length > 0 && entries.every((name) => name.startsWith('type '))),
    };
  });
}

test('transport, storage, workers and shared primitives do not import presentation runtime', () => {
  const core = files(source).filter((path) => {
    const name = relative(source, path).replaceAll('\\', '/');
    return (
      name.endsWith('.ts') &&
      (name.startsWith('remember/') ||
        name.startsWith('shared/') ||
        name.endsWith('-worker.ts') ||
        /\/(?:[^/]*-)?protocol\.ts$/u.test(name) ||
        /\/(?:socket|channel|source-transfer|recording-runtime-owner|recording-preview|artifact-secrets)\.ts$/u.test(
          name,
        ))
    );
  });
  for (const required of [
    'remember/client.ts',
    'shared/uuid.ts',
    'terminal/socket.ts',
    'management/channel.ts',
    'artifacts/evidence-worker.ts',
    'artifacts/recording-runtime-owner.ts',
    'artifacts/recording-preview.ts',
    'artifacts/artifact-secrets.ts',
  ]) {
    assert(core.includes(join(source, required)), `core coverage missing: ${required}`);
  }
  for (const path of core) {
    for (const entry of imports(path).filter((entry) => !entry.typeOnly)) {
      assert(
        !/(?:^|\/)ui\//u.test(entry.specifier),
        `${relative(source, path)} imports UI runtime: ${entry.specifier}`,
      );
      assert(
        !/^react(?:\/|$)/u.test(entry.specifier),
        `${relative(source, path)} imports React runtime`,
      );
    }
  }
});

test('workspace and evidence contracts do not depend on component implementation files', () => {
  for (const path of [
    join(source, 'workspace/model.ts'),
    join(source, 'artifacts/evidence-view.ts'),
  ]) {
    for (const entry of imports(path)) {
      if (entry.specifier.startsWith('.')) {
        const target = resolve(dirname(path), entry.specifier);
        assert(
          !existsSync(`${target}.tsx`),
          `${relative(source, path)} imports a TSX implementation: ${entry.specifier}`,
        );
      }
    }
  }
});
