import { createContext, useContext, useLayoutEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { profileResetEvent } from '../ui/profile-reset';
import type { VerifiedArtifact } from './evidence-protocol';
import { EvidenceError } from './evidence-protocol';
import type { EvidenceKey } from './verify';

// Owned by one management tab, shared ONLY by its Recording/Audit pages. Never
// indexed by username/origin, persisted, serialized, or used for authentication.
export class ArtifactSessionSecrets {
  readonly #owner: WebAccess | undefined;
  #retired = false;
  constructor(owner?: WebAccess) {
    this.#owner = owner;
  }
  #key: { file: Blob; passphrase: Uint8Array; fingerprint: string } | null = null;
  remember(key: EvidenceKey, verified: VerifiedArtifact): void {
    if (this.#retired || this.#owner?.status() === 'closed') {
      throw new EvidenceError('cancelled');
    }
    const metadata = verified.metadata;
    if (
      verified.provenance !== 'bytes-only' ||
      metadata.validation !== 'private' ||
      !['authenticated', 'no-private-records'].includes(metadata.decryption) ||
      !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(metadata.expectedRecipient) ||
      key.file.size < 1 ||
      key.file.size > 64 << 10
    ) {
      throw new EvidenceError('key');
    }
    const passphrase = new TextEncoder().encode(key.passphrase);
    if (passphrase.byteLength > 4096) {
      passphrase.fill(0);
      throw new EvidenceError('key');
    }
    this.clear();
    this.#key = { file: key.file, passphrase, fingerprint: metadata.expectedRecipient };
  }
  matching(fingerprint: string): EvidenceKey | null {
    if (this.#retired || this.#owner?.status() === 'closed') {
      this.retire();
      return null;
    }
    const cached = this.#key;
    if (cached === null || cached.fingerprint !== fingerprint) {
      return null;
    }
    return { file: cached.file, passphrase: new TextDecoder().decode(cached.passphrase) };
  }
  has(fingerprint: string): boolean {
    return (
      this.#key?.fingerprint === fingerprint && !this.#retired && this.#owner?.status() !== 'closed'
    );
  }
  fingerprint(): string | null {
    return this.#key?.fingerprint ?? null;
  }
  clear(): void {
    this.#key?.passphrase.fill(0);
    this.#key = null;
  }
  retire(): void {
    this.#retired = true;
    this.clear();
  }
  toJSON(): object {
    return { available: this.#key !== null };
  }
}
export const ArtifactSecretsContext = createContext<ArtifactSessionSecrets | null>(null);
export function useTabArtifactSecrets(
  access: WebAccess,
  signal?: AbortSignal,
): ArtifactSessionSecrets {
  const [cache, setCache] = useState(() => new ArtifactSessionSecrets(access));
  const previous = useRef(cache);
  useLayoutEffect(() => {
    // Each effect setup gets a fresh lifetime. StrictMode replay may retire its
    // previous instance, but can never resurrect it for a late worker write.
    previous.current.retire();
    const created = new ArtifactSessionSecrets(access);
    previous.current = created;
    setCache(created);
    const retire = () => created.retire();
    const unsubscribe = access.subscribeStatus(() => {
      if (access.status() === 'closed') {
        retire();
      }
    });
    signal?.addEventListener('abort', retire, { once: true });
    window.addEventListener(profileResetEvent, retire);
    if (signal?.aborted || access.status() === 'closed') {
      retire();
    }
    return () => {
      signal?.removeEventListener('abort', retire);
      window.removeEventListener(profileResetEvent, retire);
      unsubscribe();
      retire();
    };
  }, [access, signal]);
  return cache;
}
export function useArtifactSecrets(access: WebAccess): ArtifactSessionSecrets {
  const shared = useContext(ArtifactSecretsContext);
  const own = useTabArtifactSecrets(access);
  return shared ?? own;
}
