import { readFileSync } from 'node:fs';

// Use the selected source ref's inventory, not the workflow ref's platform list.
// Historical release CLIs emit one entry per edition with the same output names.
const lines = readFileSync(process.argv[2], 'utf8').trimEnd().split(/\r?\n/);
const names = ['binary-host-matrix', 'binary-container-matrix'];
const targets = new Map();
const variants = new Set();
for (const name of names) {
    const matching = lines.filter((line) => line.startsWith(`${name}=`));
    if (matching.length !== 1) {
        throw new Error(`Expected exactly one ${name}`);
    }
    const matrix = JSON.parse(matching[0].slice(name.length + 1));
    if (Object.keys(matrix).join() !== 'include' || !Array.isArray(matrix.include)) {
        throw new Error(`Invalid ${name}`);
    }
    for (const entry of matrix.include) {
        const { os, arch, edition, runner, image } = entry;
        if (
            Object.keys(entry).sort().join() !== 'arch,edition,image,os,runner' ||
            ![os, arch, edition].every(
                (value) => typeof value === 'string' && /^[a-z0-9]+$/.test(value),
            ) ||
            typeof runner !== 'string' ||
            !runner ||
            typeof image !== 'string' ||
            (name === 'binary-container-matrix') !== Boolean(image)
        ) {
            throw new Error(`Invalid binary entry in ${name}`);
        }
        const key = `${os}/${arch}`;
        const variant = `${key}/${edition}`;
        if (variants.has(variant)) {
            throw new Error(`Duplicate binary variant ${variant}`);
        }
        variants.add(variant);
        const target = targets.get(key) ?? { os, arch, runner, image, editions: [] };
        if (target.runner !== runner || (target.image && image && target.image !== image)) {
            throw new Error(`Incompatible build environments for ${key}`);
        }
        // The prepared Extended image also builds Generic with CGO_ENABLED=0.
        // Never silently choose between two different prepared images/runners.
        target.image ||= image;
        target.editions.push(edition);
        targets.set(key, target);
    }
}
if (!targets.size) {
    throw new Error('Empty binary inventory');
}
const entries = [...targets.values()];
for (const entry of entries) {
    entry.editions.sort();
}
// Emit only after validating both matrices, so failures cannot publish a partial inventory.
for (const line of lines) {
    const name = names.find((value) => line.startsWith(`${value}=`));
    if (name) {
        const container = name === 'binary-container-matrix';
        console.log(
            `${name}=${JSON.stringify({ include: entries.filter((entry) => Boolean(entry.image) === container) })}`,
        );
    } else {
        console.log(line);
    }
}
