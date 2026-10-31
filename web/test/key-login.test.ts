import { afterEach, describe, expect, it, vi } from 'vitest';
import type { LoginKey } from '../src/remember';
import { BrowserClient } from '../src/remember';
import type { Transport } from '../src/remember/http';
import { decode64, encode64 } from '../src/remember/protocol';
import { required } from './required';

const scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
const attemptToken = `bwl1.${'A'.repeat(43)}`;
const accessToken = `bwa1.${'A'.repeat(43)}`;
const encoder = new TextEncoder();
const prefix = 'bifroest-http-public-key-v1\0';
function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function wire(...values: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const size = values.reduce((size, value) => size + 4 + value.length, 0);
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const value of values) {
    new DataView(bytes.buffer).setUint32(offset, value.length);
    offset += 4;
    bytes.set(value, offset);
    offset += value.length;
  }
  return bytes;
}

class KeyServer {
  expiry = new Date(Date.now() + 110_000).toISOString();
  publicKey = encode64(wire(encoder.encode('ssh-ed25519'), new Uint8Array(32)));
  challenge = '';
  proof = encode64(wire(encoder.encode('ssh-ed25519'), new Uint8Array(64)));
  signatureCalls = 0;
  replies = 0;
  polls = 0;
  cancelled = 0;
  claimed = false;
  user = '';
  lostReply = false;
  lostPoll = false;
  duplicate = false;
  wrongStep = false;
  earlyClaim = false;
  mutate: ((text: string) => string) | undefined;
  records: { action: string; body: Record<string, string>; headers: Headers }[] = [];
  async prepare() {
    const fp = encode64(
      new Uint8Array(await crypto.subtle.digest('SHA-256', decode64(this.publicKey, 8192))),
    ).replace(/=+$/u, '');
    const body = {
      origin: scope.origin,
      slug: scope.slug,
      user: this.user,
      connectionId: '9c77b24c-62f4-44c2-aea3-771c75e5a107',
      publicKeyFingerprint: `SHA256:${fp}`,
      nonce: 'A'.repeat(43),
      expiresAt: this.expiry,
    };
    const text = prefix + JSON.stringify(body);
    this.challenge = encode64(encoder.encode(this.mutate?.(text) ?? text));
    return this;
  }
  key: LoginKey = {
    publicKey: this.publicKey,
    sign: async (challenge, expiry) => {
      this.signatureCalls++;
      expect(challenge).toBe(this.challenge);
      expect(expiry).toBe(this.expiry);
      return this.proof;
    },
  };
  pending(start = false) {
    return {
      status: 'pending',
      expiresAt: this.expiry,
      pollAfterMillis: 1000,
      ...(start ? { attemptToken } : {}),
      ...(!this.earlyClaim && (this.replies === 0 || this.duplicate)
        ? {
            step: this.wrongStep
              ? {
                  sequence: '1',
                  kind: 'prompt',
                  message: 'must never ask for a password',
                  echo: false,
                }
              : { sequence: '1', kind: 'public-key', echo: false, challenge: this.challenge },
          }
        : {}),
    };
  }
  fetch: Transport = async (input, init) => {
    const action = required(new URL(String(input)).pathname.split('/api/v1/')[1]);
    const body = JSON.parse(required(init).body as string) as Record<string, string>;
    const headers = new Headers(init?.headers);
    this.records.push({ action, body, headers });
    expect(init).toMatchObject({
      credentials: 'omit',
      mode: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    });
    if (action === 'login/public-key') {
      return json(this.pending(true), 202);
    }
    expect(headers.get('Authorization')).toBe(`Bearer ${attemptToken}`);
    if (action === 'login/cancel') {
      this.cancelled++;
      return new Response(null, { status: 204 });
    }
    if (action === 'login/reply') {
      this.replies++;
      expect(body.signature).toBe(this.proof);
      expect(body.answer).toBeUndefined();
      if (this.lostReply) {
        throw new Error('lost signature response');
      }
      return json(this.pending(), 202);
    }
    if (action === 'login/poll') {
      this.polls++;
      if (this.replies === 0 && !this.earlyClaim) {
        return json(this.pending());
      }
      if (this.claimed) {
        return json({}, 401);
      }
      this.claimed = true;
      if (this.lostPoll) {
        throw new Error('lost final claim');
      }
      return json({
        status: 'authorized',
        scope,
        principal: 'verified-actor',
        environment: 'terminal',
        terminalAvailable: true,
        expiresAt: this.expiry,
        accessToken,
      });
    }
    return json({}, 404);
  };
  client() {
    return new BrowserClient(scope, this.fetch);
  }
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('public-key login adapter (no imported-key UI/runtime claim)', () => {
  it('diagnoses unavailable WebCrypto before contacting authentication or calling a signer', async () => {
    const server = await new KeyServer().prepare();
    vi.stubGlobal('crypto', { subtle: undefined });
    await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
      code: 'unavailable',
      phase: 'browser-crypto',
    });
    expect(server.records).toHaveLength(0);
    expect(server.signatureCalls).toBe(0);
  });
  it('passes only public wire key and one SSH signature, preserving the original empty user', async () => {
    const server = await new KeyServer().prepare();
    const key = { ...server.key, privateKey: 'must-not-travel', passphrase: 'must-not-travel' };
    const access = await server.client().publicKey('', key);
    expect(access.snapshot().principal).toBe('verified-actor');
    expect(server.signatureCalls).toBe(1);
    expect(server.replies).toBe(1);
    expect(server.polls).toBe(1);
    expect(server.cancelled).toBe(0);
    expect(required(server.records[0]).body).toEqual({
      slug: 'Work',
      user: '',
      publicKey: server.publicKey,
    });
    expect(required(server.records[1]).body).toEqual({
      slug: 'Work',
      sequence: '1',
      signature: server.proof,
    });
    expect(JSON.stringify(server.records)).not.toContain('must-not-travel');
    expect(JSON.stringify(access)).not.toContain(accessToken);
  });

  it('refuses foreign, duplicated, null, expired and wrong-domain challenges before calling the signer', async () => {
    const variants = [
      (text: string) => text.replace('app.example.org', 'evil.example.org'),
      (text: string) => text.replace(':8443', ':8444'),
      (text: string) => text.replace('"Work"', '"work"'),
      (text: string) => text.replace('"user":""', '"user":"alice"'),
      (text: string) => text.replace('"user":""', '"user":"alice","user":""'),
      (text: string) => text.replace('"user":""', '"user":null'),
      (text: string) => text.replace('"user":""', '"user":"","rights":"admin"'),
      (text: string) => text.replace('"user":""', '"user":"\\ud800"'),
      (text: string) => text.replace('SHA256:', 'SHA256:wrong'),
      (text: string) => text.replace(prefix, 'bifroest-browser-remember-v1\0'),
      (text: string) => `${text}\n`,
      (text: string) => text.replace(/"nonce":"[A-Za-z0-9_-]+"/u, '"nonce":"bad"'),
      (text: string) =>
        text.replace(
          '9c77b24c-62f4-44c2-aea3-771c75e5a107',
          '00000000-0000-0000-0000-000000000000',
        ),
    ];
    for (const mutate of variants) {
      const server = new KeyServer();
      server.mutate = mutate;
      await server.prepare();
      await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
        code: 'invalid-proof',
        phase: 'challenge',
      });
      expect(server.signatureCalls).toBe(0);
      expect(server.replies).toBe(0);
      expect(server.cancelled).toBe(1);
    }
    for (const offset of [-1, 121_000]) {
      const server = new KeyServer();
      server.expiry = new Date(Date.now() + offset).toISOString();
      await server.prepare();
      await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
        code: 'invalid-proof',
      });
      expect(server.signatureCalls).toBe(0);
    }
  });

  it('accepts Go JSON escaped strings without reserializing the original challenge', async () => {
    const server = new KeyServer();
    server.user = '<"\\😀>';
    server.mutate = (text) => text.replaceAll('<', '\\u003c').replaceAll('>', '\\u003e');
    await server.prepare();
    await server.client().publicKey(server.user, server.key);
    expect(server.signatureCalls).toBe(1);
  });

  it('never falls back to an interactive prompt or signs a repeated key step', async () => {
    for (const mode of ['wrongStep', 'duplicate'] as const) {
      const server = await new KeyServer().prepare();
      server[mode] = true;
      await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
        code: 'invalid-step',
      });
      expect(server.signatureCalls).toBe(mode === 'wrongStep' ? 0 : 1);
      expect(server.cancelled).toBe(1);
    }
  });

  it('does not infer public-key access from an authorized response before its own proof reply', async () => {
    const server = await new KeyServer().prepare();
    server.earlyClaim = true;
    await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
      code: 'invalid-step',
    });
    expect(server.signatureCalls).toBe(0);
    expect(server.replies).toBe(0);
    expect(server.polls).toBe(1);
  });

  it('rejects P1363/ASN1, SHA1, malformed Base64 and trailing wire fields before posting a reply', async () => {
    for (const proof of [
      encode64(new Uint8Array(64)),
      encode64(wire(encoder.encode('ssh-rsa'), new Uint8Array(256))),
      encode64(wire(encoder.encode('ssh-ed25519'), new Uint8Array(64), new Uint8Array(1))),
      'not base64',
      encode64(wire(encoder.encode('ssh-ed25519'), new Uint8Array(0))),
    ]) {
      const server = await new KeyServer().prepare();
      server.proof = proof;
      await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
        code: 'invalid-proof',
      });
      expect(server.replies).toBe(0);
      expect(server.cancelled).toBe(1);
    }
  });

  it('never replays a signature reply or one-time final claim after an unknown outcome', async () => {
    for (const mode of ['lostReply', 'lostPoll'] as const) {
      const server = await new KeyServer().prepare();
      server[mode] = true;
      await expect(server.client().publicKey('', server.key)).rejects.toMatchObject({
        code: 'login-unknown',
      });
      expect(server.signatureCalls).toBe(1);
      expect(server.replies).toBe(1);
      expect(server.polls).toBe(mode === 'lostPoll' ? 1 : 0);
      expect(server.cancelled).toBe(1);
      expect(server.records.some((record) => record.action === 'logout')).toBe(false);
    }
  });

  it('retires a blocked signer on cancellation and serializes interactive/key attempts together', async () => {
    const server = await new KeyServer().prepare();
    const client = server.client();
    const controller = new AbortController();
    let ready!: () => void;
    let finish!: (proof: string) => void;
    const started = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const key = {
      publicKey: server.publicKey,
      sign: async (_challenge: string, _expiry: string, stopped: AbortSignal) => {
        expect(stopped.aborted).toBe(false);
        ready();
        return new Promise<string>((resolve) => {
          finish = resolve;
        });
      },
    };
    const operation = client.publicKey('', key, controller.signal);
    await started;
    await expect(client.interactive('', async () => '')).rejects.toMatchObject({ code: 'busy' });
    await expect(client.publicKey('', key)).rejects.toMatchObject({ code: 'busy' });
    controller.abort();
    await expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    finish(server.proof);
    await Promise.resolve();
    expect(server.replies).toBe(0);
    expect(server.cancelled).toBe(1);
  });

  it('enforces the hard two-minute attempt cap independently of a non-cooperative signer', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    // Native AbortSignal.timeout is not intercepted by Vitest's fake clock.
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), milliseconds);
      return controller.signal;
    });
    const server = await new KeyServer().prepare();
    let ready!: () => void;
    const started = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const operation = server.client().publicKey('', {
      publicKey: server.publicKey,
      sign: async () => {
        ready();
        return new Promise(() => {});
      },
    });
    const observed = expect(operation).rejects.toMatchObject({ code: 'denied' });
    await started;
    await vi.advanceTimersByTimeAsync(120_001);
    await observed;
    expect(server.cancelled).toBe(1);
    expect(server.replies).toBe(0);
  });
});
