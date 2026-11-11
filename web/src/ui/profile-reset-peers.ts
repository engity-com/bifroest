import { newViewID, resourceID, uuidEqual, uuidText } from '../shared/uuid';
import type { ProfileResetResult } from './profile-reset';

const channelName = 'bifroest-profile-reset-v1';
const documentID = newViewID();
function openChannel(): BroadcastChannel | null {
  try {
    return typeof BroadcastChannel === 'function' ? new BroadcastChannel(channelName) : null;
  } catch {
    return null;
  }
}
const uuid = resourceID;
const result = (value: unknown): value is ProfileResetResult =>
  value !== null &&
  typeof value === 'object' &&
  Object.keys(value).sort().join(',') === 'localCleared,remoteUnconfirmed,viewsClosed' &&
  typeof (value as ProfileResetResult).localCleared === 'boolean' &&
  typeof (value as ProfileResetResult).viewsClosed === 'boolean' &&
  Number.isSafeInteger((value as ProfileResetResult).remoteUnconfirmed) &&
  (value as ProfileResetResult).remoteUnconfirmed >= 0 &&
  (value as ProfileResetResult).remoteUnconfirmed <= 4096;

export function observeProfileResets(
  reset: (covered: readonly string[]) => Promise<ProfileResetResult>,
): () => void {
  const channel = openChannel();
  if (!channel) {
    return () => {};
  }
  const seen = new Set<string>();
  channel.onmessage = (event) => {
    const message = event.data;
    if (
      message === null ||
      typeof message !== 'object' ||
      Object.keys(message).sort().join(',') !== 'covered,id,sender,type' ||
      message.type !== 'reset' ||
      uuidEqual(message.sender, documentID) ||
      !uuid(message.sender) ||
      !uuid(message.id) ||
      !Array.isArray(message.covered) ||
      message.covered.length > 256 ||
      !message.covered.every(
        (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value),
      ) ||
      seen.has(uuidText(message.id))
    ) {
      return;
    }
    seen.add(uuidText(message.id));
    if (seen.size > 32) {
      const oldest = seen.values().next().value;
      if (oldest) {
        seen.delete(oldest);
      }
    }
    const reply = (type: string, extra: object = {}) => {
      try {
        channel.postMessage({ type, id: message.id, sender: documentID, ...extra });
      } catch {}
    };
    reply('ack');
    void reset(message.covered).then(
      (value) => reply('done', { result: value }),
      () =>
        reply('done', {
          result: { localCleared: false, remoteUnconfirmed: 1, viewsClosed: false },
        }),
    );
  };
  return () => channel.close();
}

// Event-driven peer acknowledgement, not polling. Only hashes of delegated
// binding selectors cross the channel; no token, key, password or flow name.
export function notifyProfileResetPeers(covered: readonly string[]): {
  finish(signal: AbortSignal): Promise<readonly ProfileResetResult[]>;
  close(): void;
} {
  const channel = openChannel();
  if (!channel) {
    return { finish: async () => [], close: () => {} };
  }
  const id = newViewID();
  const peers = new Map<string, ProfileResetResult | null>();
  let overflow = false;
  let grace = false;
  let wake = () => {};
  const timer = setTimeout(() => {
    grace = true;
    wake();
  }, 250);
  channel.onmessage = (event) => {
    const message = event.data;
    if (
      message === null ||
      typeof message !== 'object' ||
      !uuidEqual(message.id, id) ||
      uuidEqual(message.sender, documentID) ||
      !uuid(message.sender) ||
      !['ack', 'done'].includes(message.type) ||
      Object.keys(message).sort().join(',') !==
        (message.type === 'ack' ? 'id,sender,type' : 'id,result,sender,type')
    ) {
      return;
    }
    const sender = uuidText(message.sender);
    if (!peers.has(sender) && peers.size >= 64) {
      overflow = true;
      wake();
      return;
    }
    if (message.type === 'ack') {
      if (!peers.has(sender)) {
        peers.set(sender, null);
      }
    } else if (result(message.result)) {
      peers.set(sender, message.result);
    }
    wake();
  };
  try {
    channel.postMessage({ type: 'reset', id, sender: documentID, covered });
  } catch {
    clearTimeout(timer);
    channel.close();
    return { finish: async () => [], close: () => {} };
  }
  return {
    finish: (signal) =>
      new Promise((resolve) => {
        const check = () => {
          if ((grace && [...peers.values()].every((value) => value !== null)) || signal.aborted) {
            signal.removeEventListener('abort', check);
            resolve(
              [...peers.values()]
                .map(
                  (value) =>
                    value ?? { localCleared: false, remoteUnconfirmed: 1, viewsClosed: false },
                )
                .concat(
                  overflow
                    ? [{ localCleared: false, remoteUnconfirmed: 1, viewsClosed: false }]
                    : [],
                ),
            );
          }
        };
        wake = check;
        signal.addEventListener('abort', check, { once: true });
        check();
      }),
    close: () => {
      clearTimeout(timer);
      channel.close();
    },
  };
}
