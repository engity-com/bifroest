import { describe, expect, it } from 'vitest';
import { BrowserClient } from '../src/remember';
import type { Transport } from '../src/remember/http';

const scope = { origin: 'https://app.example.org', slug: 'Manage' };
const token = 'bwa1.' + 'A'.repeat(43);
const item = { id: '9c77b24c-62f4-44c2-aea3-771c75e5a107', flow: 'work', state: 'authorized', user: 'REQUESTED', remote: 'REQUESTED@127.0.0.1', createdAt: '2026-01-01T00:00:00Z', owner: { issuer: 'verified-issuer', subject: 'subject-not-requester' } };
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }); }
function fixture(environment = 'management', changed?: (value: unknown) => unknown) {
  const requests: { path: string; body: Record<string, string> }[] = [];
  const fetch: Transport = async (input, init) => {
    const path = new URL(String(input)).pathname.split('/api/v1/')[1]!, body = JSON.parse(init!.body as string) as Record<string, string>;
    requests.push({ path, body });
    expect(init).toMatchObject({ credentials: 'omit', redirect: 'error', cache: 'no-store', mode: 'same-origin' });
    if (path === 'login/password') return json({ status: 'authorized', accessToken: token, scope, expiresAt: new Date(Date.now() + 600_000).toISOString(), principal: 'manager', environment, terminalAvailable: environment === 'terminal' });
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer ' + token);
    if (path === 'logout') return new Response(null, { status: 204 });
    const result = path === 'management/flows/list' ? { version: 1, operation: 'flows.list', flows: { items: [{ name: 'work', auditlog: 'default', authorization: 'simple', environment: 'dummy' }], next: '', skipped: 0 } } : path === 'management/sessions/list' ? { version: 1, operation: 'sessions.list', sessions: { items: [item], next: '', skipped: 1 } } : { version: 1, operation: 'sessions.show', session: item };
    return json(changed?.(result) ?? result);
  };
  return { requests, client: new BrowserClient(scope, fetch) };
}

describe('bounded structured management client (no command/CLI transport)', () => {
  it('uses the existing opaque grant and keeps requester/verified owner distinct', async () => {
    const server = fixture(), access = await server.client.password('manager', 'secret');
    expect((await access.managementFlows()).items[0]!.environment).toBe('dummy');
    const page = await access.managementSessions({ state: 'all', flow: 'work' });
    expect(page.skipped).toBe(1); expect(page.items[0]!.user).toBe('REQUESTED'); expect(page.items[0]!.owner!.subject).toBe('subject-not-requester');
    expect(Object.isFrozen(page.items)).toBe(true); expect(Object.isFrozen(page.items[0]!.owner)).toBe(true);
    expect((await access.managementSession(item.flow, item.id)).id).toBe(item.id);
    for (const request of server.requests.slice(1)) { expect(request.body.slug).toBe('Manage'); expect(request.body.args).toBeUndefined(); expect(request.body.command).toBeUndefined(); expect(Object.values(request.body)).not.toContain(token); }
    expect(JSON.stringify(access)).not.toContain(token);
  });

  it('does not emit management calls for terminal grants, invalid filters, or a closed access', async () => {
    const terminal = fixture('terminal'), wrong = await terminal.client.password('', '');
    await expect(wrong.managementFlows()).rejects.toMatchObject({ code: 'denied' }); expect(terminal.requests).toHaveLength(1);
    const server = fixture(), access = await server.client.password('', '');
    for (const options of [{ limit: 21 }, { limit: 0 }, { after: 'other-token' }]) await expect(access.managementFlows(options)).rejects.toMatchObject({ code: 'unavailable' });
    await expect(access.managementSessions({ user: 'bad\n' })).rejects.toMatchObject({ code: 'unavailable' });
    await access.logout(); await expect(access.managementSessions()).rejects.toMatchObject({ code: 'denied' });
    expect(server.requests.map(request => request.path)).toEqual(['login/password', 'logout']);
  });

  it('rejects malformed versions, mixed operations, oversize pages and misleading owner data', async () => {
    for (const change of [(value: unknown) => ({ ...value as object, version: 2 }), (value: unknown) => ({ ...value as object, operation: 'sessions.dispose' }), () => ({ version: 1, operation: 'sessions.list', sessions: { items: Array(21).fill(item), next: '', skipped: 0 } }), () => ({ version: 1, operation: 'sessions.list', sessions: { items: [{ ...item, owner: { issuer: '', subject: 'made-up' } }], next: '', skipped: 0 } })]) {
      const server = fixture('management', change), access = await server.client.password('', '');
      await expect(access.managementSessions()).rejects.toMatchObject({ code: 'unavailable' });
      expect(server.requests).toHaveLength(2);
    }
  });
});
