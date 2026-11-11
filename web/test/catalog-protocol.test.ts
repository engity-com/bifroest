import { describe, expect, it } from 'vitest';
import {
  page,
  type RecordingOptions,
  type RecordingSummary,
  recordingFields,
} from '../src/management/protocol';

const row = {
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
function decode(value: unknown) {
  return page<RecordingSummary>(
    {
      version: 1,
      operation: 'recordings.list',
      recordings: { items: [value], next: '', skipped: 0 },
    },
    'recordings',
    20,
  ).items[0];
}

describe('recording catalog strict optional context and bounded server query', () => {
  it('preserves unknown legacy fields and accepts only explicit unencrypted context', () => {
    expect(decode(row)).toEqual(row);
    const context = {
      ...row,
      flow: 'work',
      sessionId: row.id,
      user: 'älice',
      target: 'host.example.org',
    };
    expect(decode(context)).toEqual(context);
    expect(Object.isFrozen(decode(context))).toBe(true);
    expect(decode({ ...row, metadataUnavailable: true })).toEqual({
      ...row,
      metadataUnavailable: true,
    });
  });

  it('withholds encrypted private context and never accepts server trust claims', () => {
    const encrypted = {
      ...row,
      format: 'becast-cbor/v1',
      encrypted: true,
      verificationScope: 'outer',
      recipientFingerprint: `SHA256:${'A'.repeat(43)}`,
      metadataUnavailable: true,
    };
    expect(decode(encrypted)).toEqual(encrypted);
    for (const context of [
      { flow: 'work' },
      { user: 'alice' },
      { target: 'host' },
      { sessionId: row.id },
    ]) {
      expect(() => decode({ ...encrypted, ...context })).toThrow();
      expect(() => decode({ ...row, metadataUnavailable: true, ...context })).toThrow();
    }
    for (const context of [
      { trusted: true },
      { evidence: true },
      { privateKey: 'private' },
      { owner: { subject: 'alice' } },
      { metadataUnavailable: false },
      { flow: '' },
      { flow: 'é'.repeat(128) },
      { flow: '\ud800' },
      { user: 'a\nsecret' },
      { user: 'é'.repeat(129) },
      { target: 'a'.repeat(1025) },
      { sessionId: '00000000-0000-0000-0000-000000000000' },
      { sessionId: '1111111111111111' },
    ]) {
      expect(() => decode({ ...row, ...context })).toThrow();
    }
    expect(decode({ ...row, sessionId: row.id.toUpperCase() })?.sessionId).toBe(
      row.id.toUpperCase(),
    );
  });

  it('rejects normalized impossible dates, non-ISO values, reversed nanosecond bounds and implausible counts', () => {
    for (const startedAt of [
      '2026-02-30T00:00:00Z',
      '2026-01-01',
      'January 1 2026',
      '2026-01-01T00:00:00+00:00',
      '2026-01-01T24:00:00Z',
      '1969-12-31T23:59:59Z',
      '2026-01-01T00:00:00.1234567890Z',
    ]) {
      expect(() => decode({ ...row, startedAt })).toThrow();
      expect(() => recordingFields({ startedFrom: startedAt })).toThrow();
    }
    expect(() => decode({ ...row, endedAt: '2025-12-31T23:59:59Z' })).toThrow();
    expect(() =>
      decode({
        ...row,
        startedAt: '2026-01-01T00:00:00.000000002Z',
        endedAt: '2026-01-01T00:00:00.000000001Z',
      }),
    ).toThrow();
    expect(() => decode({ ...row, chunkCount: (1 << 18) + 1 })).toThrow();
    expect(() =>
      recordingFields({
        startedFrom: '2026-01-01T00:00:00.000000002Z',
        startedUntil: '2026-01-01T00:00:00.000000001Z',
      }),
    ).toThrow();
    expect(
      recordingFields({
        startedFrom: '2026-01-01T00:00:00.000000001Z',
        startedUntil: '2026-01-01T00:00:00.000000001Z',
      }).startedFrom,
    ).toBe('2026-01-01T00:00:00.000000001Z');
  });

  it('exports exact defaults and validates UTF-8, statuses, sort and mandatory page bounds', () => {
    expect(recordingFields({})).toEqual({
      limit: '20',
      after: '',
      flow: '',
      user: '',
      target: '',
      startedFrom: '',
      startedUntil: '',
      status: 'all',
      sort: 'started-desc',
    });
    const options: RecordingOptions = {
      limit: 1,
      after: 'bmp1.AA',
      flow: 'work',
      user: 'älice',
      target: 'host',
      startedFrom: '2026-01-01T00:00:00Z',
      startedUntil: '2026-02-01T00:00:00Z',
      status: 'failed',
    };
    expect(recordingFields(options)).toEqual({ ...options, limit: '1', sort: 'started-desc' });
    for (const invalid of [
      { limit: 0 },
      { limit: 21 },
      { limit: 1.5 },
      { after: 'private-path' },
      { after: `bmp1.${'A'.repeat(4096)}` },
      { flow: '\ud800' },
      { user: '\u0000' },
      { user: 'é'.repeat(129) },
      { target: 'x'.repeat(1025) },
      { status: 'running' },
      { sort: 'uuid' },
    ]) {
      expect(() => recordingFields(invalid as RecordingOptions)).toThrow();
    }
  });
});
