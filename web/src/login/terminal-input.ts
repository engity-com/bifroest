import type { LoginStep } from './interactive';

const encoder = new TextEncoder();

// Authentication messages are text, not a remote terminal program. In
// particular a provider must not inject OSC, cursor moves, title or paste modes.
export function authenticationText(text: string): string {
  return Array.from(text.replace(/\r\n|\r|\n/gu, '\n'), (char) => {
    if (char === '\t') {
      return '    ';
    }
    const code = char.charCodeAt(0);
    if (char === '\n' || (code >= 32 && !(code >= 127 && code <= 159))) {
      return char;
    }
    return code < 32
      ? String.fromCharCode(0x2400 + code)
      : code === 127
        ? '␡'
        : `\\u${code.toString(16).padStart(4, '0')}`;
  })
    .join('')
    .replaceAll('\n', '\r\n');
}

export interface AuthenticationInputResult {
  readonly display: string;
  readonly answer?: string;
  readonly cancelled?: boolean;
  readonly limited?: boolean;
}

// Local prompt editing only, never primary authentication or a permission
// decision. Secrets live here transiently, not React state or terminal output.
export class AuthenticationInput {
  #step: LoginStep | null = null;
  #value = '';
  #bytes = 0;
  #closed = true;

  reset(step: LoginStep | null) {
    this.clear();
    this.#step = step;
    this.#closed = step === null;
  }
  clear() {
    this.#value = '';
    this.#bytes = 0;
    this.#step = null;
    this.#closed = true;
  }
  consume(data: string): AuthenticationInputResult {
    if (data.includes('\x03') || data.includes('\x04')) {
      this.clear();
      return { display: '\r\n', cancelled: true };
    }
    if (this.#closed || this.#step === null) {
      return { display: '' };
    }
    if (data.length > 4096 || !data.isWellFormed()) {
      this.clear();
      return { display: '', cancelled: true, limited: true };
    }
    // Cursor/function keys are not password bytes, and no bracketed-paste mode
    // is enabled in this local console. Do not interpret escape sequences.
    if (data.includes('\x1b')) {
      return { display: '' };
    }
    let display = '';
    for (const char of data) {
      if (char === '\r' || char === '\n') {
        const answer = this.#step.kind === 'prompt' ? this.#value : '';
        this.clear(); // Close this gate before any async reply or next prompt.
        return { display: `${display}\r\n`, answer }; // Drop the rest of this input/paste batch.
      }
      if (this.#step.kind !== 'prompt') {
        continue;
      }
      if (char === '\b' || char === '\x7f') {
        const previous = Array.from(this.#value).at(-1);
        if (previous) {
          this.#value = this.#value.slice(0, -previous.length);
          this.#bytes -= encoder.encode(previous).byteLength;
          if (this.#step.echo) {
            display += '\b \b';
          }
        }
      } else if (
        char.charCodeAt(0) >= 32 &&
        !(char.charCodeAt(0) >= 127 && char.charCodeAt(0) <= 159)
      ) {
        const bytes = encoder.encode(char).byteLength;
        if (this.#bytes + bytes > 4096) {
          this.clear();
          return { display, cancelled: true, limited: true };
        }
        this.#value += char;
        this.#bytes += bytes;
        if (this.#step.echo) {
          display += char;
        }
      }
    }
    return { display };
  }
}
