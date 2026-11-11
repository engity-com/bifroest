import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { observeTerminalResults } from './terminal-results.mjs';

function fixture() {
  const page = new EventEmitter();
  const observed = observeTerminalResults(page);
  const socket = new EventEmitter();
  socket.url = () => 'wss://app.example.org/api/v1/terminal';
  page.emit('websocket', socket);
  const control = (message) => socket.emit('framereceived', { payload: JSON.stringify(message) });
  control({ type: 'ready', connectionId: '7Xng23oeg4L1zHaZfeX6wB' });
  return { page, observed, socket, control };
}

test('keeps complete server stdout/stderr across a zero-exit UI disposal, never client opening proofs', () => {
  const { observed, socket, control } = fixture();
  socket.emit('framesent', { payload: 'PRIVATE-OPENING-PROOF' });
  socket.emit('framereceived', { payload: Buffer.from([0, 0xe2]) });
  socket.emit('framereceived', { payload: Buffer.from([0, 0x82, 0xac, 13, 10]) });
  socket.emit('framereceived', { payload: Buffer.from('\x01stderr\r\n') });
  control({ type: 'exit', status: 0 });
  socket.emit('close');
  const result = observed.latest();
  assert.equal(observed.results.length, 1);
  assert.equal(result.status, 0);
  assert.equal(result.closed, true);
  assert.equal(result.error, null);
  assert.equal(result.text(), '€\r\nstderr\r\n');
  assert(!result.text().includes('PRIVATE-OPENING-PROOF'));
});

test('does not invent an exit for an interrupted socket and rejects late output', () => {
  const first = fixture();
  first.socket.emit('close');
  assert.equal(first.observed.latest().status, null);
  const second = fixture();
  second.control({ type: 'exit', status: 7 });
  second.socket.emit('framereceived', { payload: Buffer.from('\x00late') });
  assert.equal(second.observed.latest().error, 'invalid or late terminal output');
});

test('bounds observed output without truncating it into a successful result', () => {
  const { observed, socket } = fixture();
  socket.emit('framereceived', { payload: Buffer.alloc((1 << 20) + 2) });
  assert.equal(observed.latest().error, 'fixture output exceeds the observation bound');
  assert.equal(observed.latest().text(), '');
});
