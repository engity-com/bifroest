import { EvidenceError } from '../artifacts/evidence-protocol';
import { keyLoginDiagnostic, publicRememberErrorCode } from '../login/diagnostic';
import { RememberMeError } from '../remember/protocol';

const contexts = [
  'application',
  'bootstrap',
  'remember-storage',
  'preferences',
  'logout',
  'management-read',
  'management-mutation',
  'artifact',
  'artifact-save',
  'artifact-catalog',
  'playback',
  'terminal',
  'authentication-terminal',
  'authentication-provider',
] as const;
export type UiErrorContext = (typeof contexts)[number];
const failureCodes = [
  'unavailable',
  'protocol',
  'connection-lost',
  'server-error',
  'input-limit',
  'output-limit',
  'timeout',
  'access-required',
  'configuration',
  'logout-unknown',
  'mutation-unknown',
  'provider-error',
  'user-required',
  'render-failed',
] as const;
export type UiFailureCode = (typeof failureCodes)[number];
const evidenceCodes: readonly EvidenceError['code'][] = [
  'input',
  'key',
  'limit',
  'verification',
  'cancelled',
  'unavailable',
];

const nativeStackGetter = Object.getOwnPropertyDescriptor(new Error(), 'stack')?.get;

function publicFrames(error: unknown): string[] {
  try {
    if (!(error instanceof Error)) {
      return [];
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, 'stack');
    // Chromium exposes Error.stack through a native accessor. Do not invoke
    // caller-defined getters merely to produce a diagnostic.
    const stack =
      descriptor && 'value' in descriptor
        ? descriptor.value
        : nativeStackGetter !== undefined && descriptor?.get === nativeStackGetter
          ? nativeStackGetter.call(error)
          : undefined;
    if (typeof stack !== 'string' || stack.length > 16 << 10) {
      return [];
    }
    const loaded = new Set(
      performance.getEntriesByType('resource').flatMap((entry) => {
        try {
          const url = new URL(entry.name);
          return url.origin === location.origin &&
            !url.search &&
            !url.hash &&
            !url.username &&
            !url.password &&
            /^\/_bifroest\/files\/(?:assets\/[A-Za-z0-9_-]+\.js|browser-[a-z-]+-worker\.js|go-wasm-exec\.js)$/u.test(
              url.pathname,
            )
            ? [url.href]
            : [];
        } catch {
          return [];
        }
      }),
    );
    return stack
      .split('\n')
      .slice(1, 25)
      .flatMap((line) => {
        const match = /(?:\(|\s)(https?:\/\/[^\s()]+):(\d{1,7}):(\d{1,7})\)?$/u.exec(line);
        if (!match || !loaded.has(match[1] ?? '')) {
          return [];
        }
        // No original message, function name, arbitrary URL/query or filename.
        return [`    at ${new URL(match[1] ?? '').pathname}:${match[2]}:${match[3]}`];
      });
  } catch {
    return [];
  }
}

// A console keeps object references alive. Never hand it a raw exception/event,
// cause chain, key handle, HTTP response or caller-controlled error message.
// Preserve the real classification and only verified public asset callsites.
export function reportUiError(
  context: UiErrorContext,
  error: unknown,
  failure?: UiFailureCode,
): void {
  try {
    const selected = contexts.includes(context) ? context : 'application';
    const diagnostic = keyLoginDiagnostic(error);
    const descriptor =
      error instanceof EvidenceError ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
    const evidenceCode: unknown =
      descriptor && 'value' in descriptor ? descriptor.value : undefined;
    const code =
      diagnostic?.code ??
      publicRememberErrorCode(error) ??
      (typeof evidenceCode === 'string' &&
      evidenceCodes.includes(evidenceCode as EvidenceError['code'])
        ? evidenceCode
        : 'unavailable');
    if (code === 'cancelled' && failure === undefined) {
      return;
    }
    const reason = failure !== undefined && failureCodes.includes(failure) ? failure : code;
    const known = error instanceof RememberMeError || error instanceof EvidenceError;
    const kind = known
      ? diagnostic
        ? 'KeyLoginError'
        : error instanceof EvidenceError
          ? 'EvidenceError'
          : 'RememberMeError'
      : error instanceof TypeError
        ? 'TypeError'
        : error instanceof RangeError
          ? 'RangeError'
          : 'Error';
    const support = diagnostic ? `key/${diagnostic.phase}/${diagnostic.code}` : reason;
    const reported = Object.assign(new Error(`Bifröst ${selected}: ${support}`), {
      name: kind,
      context: selected,
      code,
      ...(diagnostic ? { phase: diagnostic.phase } : {}),
      ...(failure ? { reason } : {}),
    });
    const frames = publicFrames(error);
    reported.stack = `${kind}: ${reported.message}${frames.length ? `\n${frames.join('\n')}` : ''}`;
    console.error(`[Bifröst/${selected}]`, reported);
  } catch {
    /* Diagnostics must never affect authentication, cleanup or locks. */
  }
}
