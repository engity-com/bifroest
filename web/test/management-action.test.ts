import { describe, expect, it } from 'vitest';
import { BrowserClient } from '../src/remember';
import type { Transport } from '../src/remember/http';
import { required } from './required';

const scope = { origin: 'https://app.example.org', slug: 'Manage' };
const accessToken = `bwa1.${'A'.repeat(43)}`;
const confirmationToken = `bmc1.${'B'.repeat(42)}A`;
const target = {
  id: '9c77b24c-62f4-44c2-aea3-771c75e5a107',
  flow: 'worker',
  state: 'authorized',
  user: 'requested',
  remote: 'requested@127.0.0.1',
  createdAt: '2026-01-01T00:00:00Z',
  owner: { issuer: 'issuer', subject: 'verified' },
};
function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function fixture() {
  const records: { action: string; body: Record<string, string> }[] = [];
  let used = false;
  let drop = false;
  let changed = false;
  const fetch: Transport = async (input, init) => {
    const action = required(new URL(String(input)).pathname.split('/api/v1/')[1]);
    const body = JSON.parse(required(init).body as string) as Record<string, string>;
    records.push({ action, body });
    expect(init).toMatchObject({
      credentials: 'omit',
      mode: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    });
    if (action === 'login/password') {
      return json({
        status: 'authorized',
        accessToken,
        scope,
        principal: 'manager',
        expiresAt: new Date(Date.now() + 600000).toISOString(),
        environment: 'management',
        terminalAvailable: false,
      });
    }
    expect(new Headers(init?.headers).get('Authorization')).toBe(`Bearer ${accessToken}`);
    if (action === 'management/sessions/prepare') {
      return json(
        {
          version: 1,
          status: 'confirmation-required',
          confirmationToken,
          expiresAt: new Date(Date.now() + 60000).toISOString(),
          action: body.action,
          target: changed ? { ...target, id: '00000000-0000-0000-0000-000000000001' } : target,
        },
        202,
      );
    }
    expect(body).toEqual({ slug: 'Manage', confirmationToken });
    if (action === 'management/sessions/cancel') {
      return new Response(null, { status: 204 });
    }
    expect(action).toBe('management/sessions/confirm');
    if (used) {
      return json({}, 403);
    }
    used = true;
    if (drop) {
      throw new Error('lost final response');
    }
    return json({
      version: 1,
      status: 'completed',
      result: { id: target.id, flow: target.flow, action: 'dispose' },
    });
  };
  return {
    records,
    client: new BrowserClient(scope, fetch),
    lose() {
      drop = true;
    },
    change() {
      changed = true;
    },
  };
}

describe('one-time pinned management session action handle', () => {
  it('confirms only its original action/target/access and never serializes either permission', async () => {
    const server = fixture();
    const access = await server.client.password('manager', 'secret');
    const handle = await access.prepareSessionAction('dispose', target.flow, target.id);
    expect(JSON.stringify(handle)).not.toContain(confirmationToken);
    expect(JSON.stringify(handle)).not.toContain(accessToken);
    expect(required(handle.snapshot().target.owner).subject).toBe('verified');
    expect(Object.isFrozen(handle.snapshot().target)).toBe(true);
    expect(await handle.confirm()).toEqual({ action: 'dispose', flow: target.flow, id: target.id });
    await expect(handle.confirm()).rejects.toMatchObject({ code: 'changed' });
    expect(await handle.cancel()).toBe(false);
    expect(server.records.filter((record) => record.action.endsWith('/confirm'))).toHaveLength(1);
  });

  it('reports a lost commit as outcome unknown without retry, cancel-as-undo or logout', async () => {
    const server = fixture();
    const access = await server.client.password('manager', 'secret');
    const handle = await access.prepareSessionAction('dispose', target.flow, target.id);
    server.lose();
    await expect(handle.confirm()).rejects.toMatchObject({ code: 'management-unknown' });
    await expect(handle.confirm()).rejects.toMatchObject({ code: 'changed' });
    expect(await handle.cancel()).toBe(false);
    expect(server.records.map((record) => record.action)).toEqual([
      'login/password',
      'management/sessions/prepare',
      'management/sessions/confirm',
    ]);
  });

  it('can retire an unused preparation but cannot turn cancellation into disposal', async () => {
    const server = fixture();
    const access = await server.client.password('manager', 'secret');
    const handle = await access.prepareSessionAction('disconnect', target.flow, target.id);
    expect(await handle.cancel()).toBe(true);
    await expect(handle.confirm()).rejects.toMatchObject({ code: 'changed' });
    expect(server.records.filter((record) => record.action.endsWith('/confirm'))).toHaveLength(0);
  });

  it('refuses a response naming a different target and does not infer access from selectors', async () => {
    const server = fixture();
    const access = await server.client.password('manager', 'secret');
    server.change();
    await expect(
      access.prepareSessionAction('dispose', target.flow, target.id),
    ).rejects.toMatchObject({ code: 'denied' });
    expect(server.records.filter((record) => record.action.endsWith('/confirm'))).toHaveLength(0);
  });
});
