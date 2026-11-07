import { expect, it } from 'vitest';
import type { VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import { verifiedRecordingFlow } from '../src/artifacts/recording-flow';
import { versionInfo } from '../src/management/protocol';
import { documentationLink } from '../src/management/VersionDetails';
import { tabTitle } from '../src/terminal/tab-title';

it('links only known feature documentation, pins release versions, and uses the root docs for development', () => {
  expect(documentationLink('1.0.0-beta2', 'authorization')).toBe(
    'https://bifroest.engity.org/v1.0.0-beta2/reference/authorization/',
  );
  expect(documentationLink('v1.0.0-beta2', 'authorization', 'bifroest')).toBe(
    'https://bifroest.engity.org/v1.0.0-beta2/reference/authorization/bifroest/',
  );
  expect(documentationLink('development', 'authorization', 'local[pam]')).toBe(
    'https://bifroest.engity.org/reference/authorization/local/',
  );
  expect(documentationLink('development', 'environment', 'not-a-documented-driver')).toBeNull();
  expect(documentationLink('1.0.0', 'password-crypt', 'yescrypt')).toBeNull();
  expect(documentationLink('https://evil.invalid/', 'authorization', '../../evil')).toBeNull();
});
it('accepts bounded structured long-version JSON but refuses it in a short-version result', () => {
  const body = {
    version: 1,
    operation: 'version.show',
    versionInfo: {
      detail: 'long',
      text: 'native long version',
      build: {
        title: '<script>not markup</script>',
        version: '1.0.0-beta2',
        revision: 'HEAD',
        edition: 'generic',
        buildAt: '2026-11-05T00:00:00Z',
        vendor: 'Engity',
        go: '1.27.3',
        platform: 'linux/amd64',
        features: [{ name: 'authorization', entries: ['bifroest'] }],
      },
    },
  };
  expect(versionInfo(body, true).build?.features[0]?.entries).toEqual(['bifroest']);
  expect(() =>
    versionInfo({ ...body, versionInfo: { ...body.versionInfo, detail: 'short' } }, false),
  ).toThrow();
  expect(() =>
    versionInfo(
      {
        ...body,
        versionInfo: {
          ...body.versionInfo,
          build: { ...body.versionInfo.build, features: [{ name: 'bad', entries: [5] }] },
        },
      },
      true,
    ),
  ).toThrow();
});
it('keeps shell titles plain, bounded and free of controls or bidi spoofing', () => {
  expect(tabTitle('\u202eevil\u202c\u0007\n  shell')).toBe('evil  shell');
  expect([...tabTitle('ä'.repeat(1000))]).toHaveLength(160);
  expect(tabTitle(' <b>literal</b> ')).toBe('<b>literal</b>');
});
it('extracts flow breadcrumbs only from matching fully verified Recording output', async () => {
  const verified = {
    request: { kind: 'recording', auditlog: 'default', id: 'one' },
    provenance: 'bytes-only',
    metadata: { validation: 'private', outputFormat: 'cast' },
    output: new Blob(['{}\n# bifroest:metadata:v1 {"recordingId":"one","flow":"admin"}\n']),
  } as VerifiedArtifact;
  expect(await verifiedRecordingFlow(verified)).toBe('admin');
  expect(
    await verifiedRecordingFlow({
      ...verified,
      output: new Blob(['{}\n# bifroest:metadata:v1 {"recordingId":"other","flow":"wrong"}\n']),
    }),
  ).toBe('');
});
