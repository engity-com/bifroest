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
    const text = readFileSync(path, 'utf8');
    const declarations = [
        ...text.matchAll(/^(?:import|export)\s+(type\s+)?([^;]+?)\s+from\s+['"]([^'"]+)['"]/gmu),
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
                !!match[1] ||
                (entries.length > 0 && entries.every((name) => name.startsWith('type '))),
        };
    });
    const dynamic = [...text.matchAll(/\bimport\(\s*['"]([^'"]+)['"]/gu)].map((match) => ({
        specifier: match[1],
        typeOnly: false,
    }));
    const sideEffects = [...text.matchAll(/^import\s+['"]([^'"]+)['"]/gmu)].map((match) => ({
        specifier: match[1],
        typeOnly: false,
    }));
    return [...declarations, ...dynamic, ...sideEffects];
}

test('transport, storage, workers and shared primitives do not import presentation runtime', () => {
    const core = files(source).filter((path) => {
        const name = relative(source, path).replaceAll('\\', '/');
        return (
            name.endsWith('.ts') &&
            (name.startsWith('remember/') ||
                name.startsWith('shared/') ||
                name.startsWith('application/') ||
                name === 'login/attempt.ts' ||
                /management\/(?:client|session-action-owner)\.ts$/u.test(name) ||
                /artifacts\/(?:evidence-job|evidence-document|evidence-result|prepared-playback|verify-evidence|recording-source-verification)\.ts$/u.test(
                    name,
                ) ||
                /workspace\/(?:controller|connections|state|policy)\.ts$/u.test(name) ||
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
        'application/reset-owner.ts',
        'application/navigation.ts',
        'application/link-metadata.ts',
        'login/attempt.ts',
        'management/client.ts',
        'management/session-action-owner.ts',
        'artifacts/evidence-job.ts',
        'artifacts/evidence-document.ts',
        'artifacts/evidence-result.ts',
        'artifacts/prepared-playback.ts',
        'artifacts/verify-evidence.ts',
        'artifacts/recording-source-verification.ts',
        'workspace/controller.ts',
        'workspace/connections.ts',
        'workspace/state.ts',
        'workspace/policy.ts',
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
            if (entry.specifier.startsWith('.')) {
                assert(
                    !existsSync(`${resolve(dirname(path), entry.specifier)}.tsx`),
                    `${relative(source, path)} imports a component runtime: ${entry.specifier}`,
                );
            }
        }
    }
});

test('the RememberMe entry point does not re-export artifact or management implementations', () => {
    for (const entry of imports(join(source, 'remember/index.ts'))) {
        assert(
            !/^\.\.\/(?:artifacts|management)\//u.test(entry.specifier),
            `foreign domain in RememberMe entry point: ${entry.specifier}`,
        );
    }
});

test('the standalone client bundle assembles domain tools only at its composition root', () => {
    const composition = imports(join(source, 'client.ts')).map((entry) => entry.specifier);
    assert(composition.includes('./remember'));
    assert(composition.includes('./artifacts/verify'));
    assert(composition.includes('./artifacts/prepare-playback'));
    assert.match(
        readFileSync(join(source, '../vite.config.ts'), 'utf8'),
        /entry: 'src\/client\.ts'/u,
    );
});

test('workspace and evidence contracts do not depend on component implementation files', () => {
    for (const path of [
        join(source, 'workspace/model.ts'),
        join(source, 'workspace/contracts.ts'),
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
