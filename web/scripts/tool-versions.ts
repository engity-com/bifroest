import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../../', import.meta.url));

// The catalog deliberately uses a flat mapping of quoted version strings.
// Do not execute MISE or accept environment overrides to validate build inputs.
export function readToolVersions(root = repository): ReadonlyMap<string, string> {
    const versions = new Map<string, string>();
    for (const line of readFileSync(join(root, 'mise.tools.yaml'), 'utf8').split(/\r?\n/u)) {
        if (/^\s*(?:#.*)?$/u.test(line)) {
            continue;
        }
        const match =
            /^tool_version_([a-z][a-z0-9_]*):\s*"([v0-9][0-9A-Za-z.+-]*)"\s*(?:#.*)?$/u.exec(line);
        const name = match?.[1];
        const version = match?.[2];
        if (
            name === undefined ||
            version === undefined ||
            !/^v?[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?$/u.test(version) ||
            versions.has(name)
        ) {
            throw new Error('Invalid or duplicate entry in mise.tools.yaml');
        }
        versions.set(name, version);
    }
    if (versions.size === 0) {
        throw new Error('Empty mise.tools.yaml');
    }
    return versions;
}

export function toolVersion(name: string, root = repository): string {
    const version = readToolVersions(root).get(name);
    if (version === undefined) {
        throw new Error(`Missing tool version ${name} in mise.tools.yaml`);
    }
    return version;
}

export function requirePinnedNode(root = repository): void {
    const expected = toolVersion('node', root);
    if (process.versions.node !== expected) {
        throw new Error(`Tests/builds require the MISE-pinned Node ${expected} runtime`);
    }
}
