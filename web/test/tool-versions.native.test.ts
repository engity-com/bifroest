import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readToolVersions, requirePinnedNode, toolVersion } from '../scripts/tool-versions.ts';

test('tool guards follow catalog changes and still reject an unpinned runtime', (t) => {
    const root = mkdtempSync(join(tmpdir(), 'bifroest-tool-catalog-'));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const catalog = join(root, 'mise.tools.yaml');
    writeFileSync(
        catalog,
        `# Preserve MISE's flat quoted catalog.\r\ntool_version_node: "${process.versions.node}" # Node\r\ntool_version_bun: "1.4.5"\r\n`,
    );
    assert.equal(toolVersion('node', root), process.versions.node);
    assert.equal(toolVersion('bun', root), '1.4.5');
    assert.doesNotThrow(() => requirePinnedNode(root));
    writeFileSync(catalog, 'tool_version_node: "99.0.0"\n');
    assert.equal(toolVersion('node', root), '99.0.0');
    assert.throws(() => requirePinnedNode(root), /MISE-pinned Node 99\.0\.0/u);
    assert.throws(() => toolVersion('missing', root), /Missing tool version/u);
});

test('catalog parsing fails closed for empty, ambiguous or executable values', (t) => {
    const root = mkdtempSync(join(tmpdir(), 'bifroest-invalid-tool-catalog-'));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    for (const raw of [
        '',
        'tool_version_node: 26',
        'tool_version_node: "latest"',
        'tool_version_node: "{{ exec(command=\'bad\') }}"',
        'tool_version_node: "26.13.1"\ntool_version_node: "26.9.0"',
        'tool_version_node: &version "26.13.1"',
    ]) {
        writeFileSync(join(root, 'mise.tools.yaml'), raw);
        assert.throws(() => readToolVersions(root));
    }
});
