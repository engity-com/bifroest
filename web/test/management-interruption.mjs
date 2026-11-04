// Test-only loss after the REAL server has committed and completed the action.
// All frames stay byte-exact except the one deliberately lost final completion;
// no fake action response, second execution, authentication or application retry.
export async function managementInterruption(page, { holdPreparation = false } = {}) {
  let armed = null;
  let losses = 0;
  let held = null;
  await page.routeWebSocket('**/_bifroest/api/v1/management/channel', (route) => {
    const server = route.connectToServer();
    const actions = new Map();
    const successful = new Set();
    route.onMessage((message) => {
      if (typeof message === 'string') {
        const value = JSON.parse(message);
        if (value.type === 'request') {
          actions.set(value.requestId, value.action);
        }
      }
      server.send(message);
    });
    server.onMessage(async (message) => {
      const frame = typeof message === 'string' ? JSON.parse(message) : null;
      if (
        holdPreparation &&
        frame?.type === 'response' &&
        frame.status === 202 &&
        actions.get(frame.requestId) === 'management/sessions/prepare'
      ) {
        holdPreparation = false;
        held = { route, id: frame.requestId, frames: [], bytes: 0, complete: false };
      }
      const frameID =
        frame?.requestId ??
        (Buffer.isBuffer(message) && message.length >= 8
          ? message.readBigUInt64BE(0).toString()
          : null);
      if (held?.route === route && held.id === frameID) {
        held.bytes += Buffer.byteLength(message);
        if (held.bytes > 64 << 10 || held.frames.length >= 16) {
          throw new Error('held preparation exceeded fixture bound');
        }
        held.frames.push(message);
        if (frame?.type === 'complete') {
          held.complete = true;
          actions.delete(held.id);
          const acknowledged = await page.evaluate(async () => {
            const response = await fetch('/_bifroest/test/preparation-channel-entered', {
              method: 'POST',
              credentials: 'omit',
              mode: 'same-origin',
            });
            return response.status === 204;
          });
          if (!acknowledged) {
            throw new Error('preparation barrier acknowledgement failed');
          }
        }
        return;
      }
      if (typeof message === 'string') {
        const value = JSON.parse(message);
        if (value.type === 'response' && value.status === 200) {
          successful.add(value.requestId);
        }
        if (value.type === 'complete') {
          const action = actions.get(value.requestId);
          actions.delete(value.requestId);
          const confirmed = successful.delete(value.requestId);
          if (armed === action && confirmed) {
            armed = null;
            losses++;
            try {
              const acknowledged = await page.evaluate(async () => {
                const response = await fetch('/_bifroest/test/management-confirm-response-cut', {
                  method: 'POST',
                  credentials: 'omit',
                  mode: 'same-origin',
                });
                return response.status === 204;
              });
              if (!acknowledged) {
                throw new Error('response-cut fixture acknowledgement failed');
              }
            } finally {
              await Promise.allSettled([
                route.close({ code: 1011, reason: 'fixture completion lost' }),
                server.close(),
              ]);
            }
            return;
          }
        }
      }
      route.send(message);
    });
  });
  return {
    arm(action) {
      if (armed !== null) {
        throw new Error('response-cut already armed');
      }
      armed = action;
    },
    losses: () => losses,
    releasePreparation() {
      if (!held?.complete) {
        throw new Error('preparation was not fully observed');
      }
      const completed = held;
      held = null;
      for (const frame of completed.frames) {
        completed.route.send(frame);
      }
      completed.frames = [];
    },
  };
}
