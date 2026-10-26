import { describe, expect, it } from 'vitest';
import { WebAccess } from '../src/remember/client';
import type { Transport } from '../src/remember/http';
import { Http } from '../src/remember/http';
import { required } from './required';

const scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
const permission = {
  scope,
  principal: 'manager',
  expiresAt: '2100-01-01T00:00:00Z',
  environment: 'management' as const,
  terminalAvailable: false,
  accessToken: `bwa1.${'A'.repeat(43)}`,
};
const recording = {
  auditlog: 'default',
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
  producerId: 'b'.repeat(64),
  format: 'bcast/v1',
  status: 'completed',
  startedAt: '2026-01-01T00:00:00Z',
  endedAt: '2026-01-01T00:00:01Z',
  containerBytes: 1321,
  chunkCount: 1,
  encrypted: false,
  verificationScope: 'full',
};
const auditlog = { name: 'default', enabled: true, recordingEnabled: true, encrypted: false };
function envelope(kind: 'auditlogs' | 'recordings', items: unknown[], next = '') {
  return { version: 1, operation: `${kind}.list`, [kind]: { items, next, skipped: 0 } };
}
function json(value: unknown) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
function fixture(
  reply?: (kind: 'auditlogs' | 'recordings') => unknown,
  response: ConstructorParameters<typeof WebAccess>[1] = permission,
) {
  const requests: { path: string; body: Record<string, string> }[] = [];
  const transport: Transport = async (input, init) => {
    const path = new URL(String(input)).pathname;
    const body = JSON.parse(required(init).body as string) as Record<string, string>;
    requests.push({ path, body });
    expect(init).toMatchObject({
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
      mode: 'same-origin',
    });
    expect(new Headers(init?.headers).get('Authorization')).toBe(
      `Bearer ${permission.accessToken}`,
    );
    if (path.endsWith('/logout')) {
      return new Response(null, { status: 204 });
    }
    const kind = path.endsWith('/auditlogs/list') ? 'auditlogs' : 'recordings';
    return json(reply?.(kind) ?? envelope(kind, [kind === 'auditlogs' ? auditlog : recording]));
  };
  return { requests, access: new WebAccess(new Http(scope, transport), response, null) };
}

describe('catalog metadata client (not evidence verification)', () => {
  it('uses fixed scoped metadata reads and never promotes server inspection to evidence', async () => {
    const server = fixture();
    expect((await server.access.managementAuditlogs()).items).toEqual([auditlog]);
    const page = await server.access.managementRecordings('default');
    expect(page.items).toEqual([recording]);
    expect(Object.isFrozen(page.items)).toBe(true);
    expect(Object.isFrozen(required(page.items[0]))).toBe(true);
    expect('evidence' in required(page.items[0])).toBe(false);
    expect('trusted' in required(page.items[0])).toBe(false);
    expect(server.requests.map((request) => request.body)).toEqual([
      { slug: 'Work', limit: '20', after: '' },
      { slug: 'Work', auditlog: 'default', limit: '20', after: '' },
    ]);
    for (const request of server.requests) {
      expect(request.path).toMatch(/\/management\/(?:auditlogs|recordings)\/list$/u);
      expect(JSON.stringify(request)).not.toContain('bwa1.');
      expect(request.body.command).toBeUndefined();
      expect(request.body.allowArtifactTransfer).toBeUndefined();
    }
  });

  it('refuses unsupported scope, expiry, invalid selectors/pages and closed access before sending', async () => {
    const server = fixture();
    for (const name of ['', '..', '../private', 'bad/name']) {
      await expect(server.access.managementRecordings(name)).rejects.toMatchObject({
        code: 'unavailable',
      });
    }
    for (const options of [{ limit: 21 }, { limit: 0 }, { after: 'private-path' }]) {
      await expect(server.access.managementAuditlogs(options)).rejects.toMatchObject({
        code: 'unavailable',
      });
      await expect(server.access.managementRecordings('default', options)).rejects.toMatchObject({
        code: 'unavailable',
      });
    }
    expect(server.requests).toHaveLength(0);
    for (const response of [
      { ...permission, environment: 'terminal' as const },
      { ...permission, expiresAt: '2000-01-01T00:00:00Z' },
    ]) {
      const denied = fixture(undefined, response);
      await expect(denied.access.managementAuditlogs()).rejects.toMatchObject({ code: 'denied' });
      await expect(denied.access.managementRecordings('default')).rejects.toMatchObject({
        code: 'denied',
      });
      expect(denied.requests).toHaveLength(0);
    }
    await server.access.logout();
    await expect(server.access.managementAuditlogs()).rejects.toMatchObject({ code: 'denied' });
    await expect(server.access.managementRecordings('default')).rejects.toMatchObject({
      code: 'denied',
    });
    expect(server.requests).toHaveLength(1);
  });

  it('rejects wrong auditlog, malformed rows, extra private fields, duplicate/oversize pages and fake evidence', async () => {
    for (const row of [
      { ...recording, auditlog: 'other' },
      { ...recording, id: '00000000-0000-0000-0000-000000000000' },
      { ...recording, producerId: '0'.repeat(64) },
      { ...recording, status: ['completed'] },
      { ...recording, encrypted: true },
      { ...recording, verificationScope: 'private' },
      { ...recording, containerBytes: Number.MAX_SAFE_INTEGER + 1 },
      { ...recording, chunkCount: -1 },
      { ...recording, startedAt: 'not-a-time' },
      { ...recording, privateKey: 'private' },
      { ...recording, trusted: true },
    ]) {
      const server = fixture(() => envelope('recordings', [row]));
      await expect(server.access.managementRecordings('default')).rejects.toMatchObject({
        code: 'unavailable',
      });
      expect(server.requests).toHaveLength(1);
    }
    for (const value of [
      envelope('recordings', [recording, recording]),
      envelope('recordings', Array(21).fill(recording)),
      envelope('auditlogs', [auditlog]),
    ]) {
      await expect(
        fixture(() => value).access.managementRecordings('default'),
      ).rejects.toMatchObject({ code: 'unavailable' });
    }
    for (const row of [
      { ...auditlog, directory: 'private' },
      { ...auditlog, enabled: 'true' },
      { ...auditlog, name: '../private' },
    ]) {
      await expect(
        fixture(() => envelope('auditlogs', [row])).access.managementAuditlogs(),
      ).rejects.toMatchObject({ code: 'unavailable' });
    }
  });

  it('keeps encrypted server metadata opaque and rejects late replies after logout', async () => {
    const encrypted = {
      ...recording,
      encrypted: true,
      format: 'becast-cbor/v1',
      verificationScope: 'outer',
      recipientFingerprint: `SHA256:${'A'.repeat(43)}`,
    };
    expect(
      (
        await fixture(() => envelope('recordings', [encrypted])).access.managementRecordings(
          'default',
        )
      ).items,
    ).toEqual([encrypted]);
    let reply: ((response: Response) => void) | undefined;
    const waiting = new Promise<Response>((resolve) => {
      reply = resolve;
    });
    const access = new WebAccess(
      new Http(scope, async (input) =>
        String(input).endsWith('/logout') ? new Response(null, { status: 204 }) : waiting,
      ),
      permission,
      null,
    );
    const pending = access.managementRecordings('default');
    const observed = expect(pending).rejects.toMatchObject({ code: 'denied' });
    await access.logout();
    reply?.(json(envelope('recordings', [recording])));
    await observed;
  });
});
