import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { required } from './required.ts';

const source = fileURLToPath(new URL('../src/', import.meta.url));

test('application, scripts and tests share the same strict TypeScript project', () => {
    const config = JSON.parse(
        readFileSync(new URL('../tsconfig.json', import.meta.url), 'utf8'),
    ) as {
        compilerOptions: Record<string, unknown>;
        include: string[];
        exclude?: string[];
    };
    for (const option of [
        'strict',
        'noUncheckedIndexedAccess',
        'exactOptionalPropertyTypes',
        'noUnusedLocals',
        'noUnusedParameters',
    ]) {
        assert.equal(
            config.compilerOptions[option],
            true,
            `${option} applies to every source file`,
        );
    }
    for (const directory of ['src', 'scripts', 'test', '../test/pam/run.ts']) {
        assert(config.include.includes(directory), `${directory} belongs to the shared project`);
    }
    assert.deepEqual(config.exclude ?? [], []);
});

test('browser fixture globals resolve when an editor checks a single entry point', (t) => {
    const web = fileURLToPath(new URL('../', import.meta.url));
    const temporary = mkdtempSync(join(tmpdir(), 'bifroest-fixture-types-'));
    t.after(() => rmSync(temporary, { recursive: true, force: true }));
    const config = join(temporary, 'tsconfig.json');
    for (const entry of [
        'connections-ui.ts',
        'drawer-diagnostics.ts',
        'terminal-rendering.native.test.ts',
    ]) {
        writeFileSync(
            config,
            JSON.stringify({
                extends: join(web, 'tsconfig.json'),
                compilerOptions: {
                    types: [
                        join(web, 'node_modules/vite/client.d.ts'),
                        join(web, 'node_modules/@types/node/index.d.ts'),
                    ],
                },
                files: [join(web, 'test', entry)],
                include: [],
            }),
        );
        assert.doesNotThrow(
            () =>
                execFileSync(
                    process.execPath,
                    [
                        join(web, 'node_modules/typescript/bin/tsc'),
                        '--noEmit',
                        '--pretty',
                        'false',
                        '--project',
                        config,
                    ],
                    { cwd: web, encoding: 'utf8', timeout: 30_000 },
                ),
            `${entry} must import its browser globals`,
        );
    }
});

test('project-owned Node scripts use TypeScript rather than mjs', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const paths = execFileSync(
        'git',
        ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
        {
            cwd: root,
            encoding: 'utf8',
        },
    ).split('\0');
    assert.deepEqual(
        paths.filter((path) => path.endsWith('.mjs') && existsSync(join(root, path))),
        [],
    );
});

function files(directory: string): string[] {
    return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
        const path = join(directory, entry.name);
        return entry.isDirectory() ? files(path) : [path];
    });
}

test('Node entry points need only native erasable TypeScript, not a runtime loader', () => {
    const web = fileURLToPath(new URL('../', import.meta.url));
    const scripts = files(join(web, 'scripts'));
    const harness = files(join(web, 'test')).filter(
        (path) => !path.endsWith('.test.ts') || path.endsWith('.native.test.ts'),
    );
    for (const path of [...scripts, ...harness, join(web, '../test/pam/run.ts')].filter(
        (path) => path.endsWith('.ts') && !path.endsWith('.d.ts'),
    )) {
        assert.doesNotThrow(
            () => stripTypeScriptTypes(readFileSync(path, 'utf8'), { mode: 'strip' }),
            `Node must execute ${relative(web, path)} without TypeScript transforms`,
        );
    }
});

function imports(path: string) {
    const text = readFileSync(path, 'utf8');
    const declarations = [
        ...text.matchAll(/^(?:import|export)\s+(type\s+)?([^;]+?)\s+from\s+['"]([^'"]+)['"]/gmu),
    ].map((match) => {
        const names = required(match[2]).trim();
        const entries = names.startsWith('{')
            ? names
                  .slice(1, -1)
                  .split(',')
                  .map((name) => name.trim())
                  .filter(Boolean)
            : [];
        return {
            specifier: required(match[3]),
            typeOnly:
                !!match[1] ||
                (entries.length > 0 && entries.every((name) => name.startsWith('type '))),
        };
    });
    const dynamic = [...text.matchAll(/\bimport\(\s*['"]([^'"]+)['"]/gu)].map((match) => ({
        specifier: required(match[1]),
        typeOnly: false,
    }));
    const sideEffects = [...text.matchAll(/^import\s+['"]([^'"]+)['"]/gmu)].map((match) => ({
        specifier: required(match[1]),
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
                /management\/(?:client|read-model|session-action-owner)\.ts$/u.test(name) ||
                /artifacts\/(?:evidence-session|evidence-target|evidence-job|evidence-document|evidence-result|prepared-playback|verify-evidence|recording-source-verification)\.ts$/u.test(
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
        'shared/snapshot-observers.ts',
        'application/reset-owner.ts',
        'application/navigation.ts',
        'application/link-metadata.ts',
        'login/attempt.ts',
        'management/client.ts',
        'management/session-action-owner.ts',
        'management/read-model.ts',
        'artifacts/evidence-session.ts',
        'artifacts/evidence-target.ts',
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
        join(source, 'artifacts/evidence-dialogs-view.ts'),
        join(source, 'artifacts/local-key-input-view.ts'),
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

test('evidence presentation has no direct grant, worker or workflow implementation dependencies', () => {
    for (const name of [
        'EvidenceDialogs.tsx',
        'EvidenceVerificationToolbar.tsx',
        'RecordingEvidenceView.tsx',
        'AuditEvidenceView.tsx',
    ]) {
        for (const entry of imports(join(source, 'artifacts', name)).filter(
            (entry) => !entry.typeOnly,
        )) {
            assert(
                !/(?:^|\/)remember(?:\/|$)/u.test(entry.specifier),
                `${name} imports access implementation: ${entry.specifier}`,
            );
            assert(
                !/(?:^|\/)(?:verify|verify-evidence|recording-preview|recording-runtime-owner|recording-source-verification|receive|protection|evidence-session|evidence-job|evidence-document)$/u.test(
                    entry.specifier,
                ),
                `${name} imports workflow implementation: ${entry.specifier}`,
            );
        }
    }
});
