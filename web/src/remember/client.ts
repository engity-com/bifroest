import type { ArtifactRequest, ReceivedArtifact } from '../artifacts/protocol';
import { artifactFields } from '../artifacts/protocol';
import { receiveArtifact } from '../artifacts/receive';
import type { StepHandler } from '../login/interactive';
import { interactive } from '../login/interactive';
import type { LoginKey } from '../login/key';
import { publicKeyLogin } from '../login/key';
import type { SessionAction } from '../management/action';
import { actionPreparation, actionResult, SessionActionConfirmation } from '../management/action';
import { ManagementConnection } from '../management/channel';
import type {
  AuditlogSummary,
  FlowSummary,
  Page,
  PageOptions,
  RecordingOptions,
  RecordingSummary,
  SessionItem,
  SessionOptions,
  VersionInfo,
} from '../management/protocol';
import {
  auditlogName,
  detail,
  page,
  pageFields,
  recordingFields,
  sessionFields,
  versionInfo,
} from '../management/protocol';
import { type KeepAlivePolicy, keepAlivePolicy } from '../terminal/keepalive';
import type { SocketFactory, TerminalState } from '../terminal/socket';
import type { Transport } from './http';
import { Http, isToken, object, time } from './http';
import type { Binding, ProofPurpose, Scope } from './protocol';
import { decode64, RememberMeError, validateBinding } from './protocol';
import { BrowserBinding } from './store';

export interface AccessSnapshot {
  readonly scope: Scope;
  readonly principal: string;
  readonly expiresAt: string;
  readonly environment: 'terminal' | 'management';
  readonly terminalAvailable: boolean;
  readonly keepAlive?: KeepAlivePolicy;
  readonly flow?: { readonly name: string; readonly title: string };
}

export type AccessStatus = 'active' | 'expired' | 'closed';

interface AccessResponse extends AccessSnapshot {
  readonly accessToken: string;
}

export interface LogoutResult {
  readonly localState: 'removed' | 'not-owned' | 'changed' | 'unavailable';
}

async function forgetOwned(handle: BrowserBinding | null | undefined): Promise<LogoutResult> {
  if (handle === null || handle === undefined) {
    return { localState: 'not-owned' };
  }
  try {
    await handle.forgetLocal();
    return { localState: 'removed' };
  } catch (error) {
    return {
      localState:
        error instanceof RememberMeError && error.code === 'changed' ? 'changed' : 'unavailable',
    };
  }
}

function accessResponse(value: unknown, scope: Scope): AccessResponse {
  const body = object(value, [
    'status',
    'accessToken',
    'expiresAt',
    'scope',
    'principal',
    'environment',
    'terminalAvailable',
    'keepAlive',
    ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'flow')
      ? ['flow']
      : []),
  ]);
  const selected = object(body.scope, ['origin', 'slug']);
  if (
    body.status !== 'authorized' ||
    !isToken(body.accessToken, 'bwa1.') ||
    selected.origin !== scope.origin ||
    selected.slug !== scope.slug ||
    typeof body.principal !== 'string' ||
    body.principal.length > 4096 ||
    /[\p{Cc}]/u.test(body.principal) ||
    (body.environment !== 'terminal' && body.environment !== 'management') ||
    body.terminalAvailable !== (body.environment === 'terminal')
  ) {
    throw new RememberMeError('unavailable');
  }
  let flow: AccessSnapshot['flow'];
  if (body.flow !== undefined) {
    const item = object(body.flow, ['name', 'title']);
    if (
      typeof item.name !== 'string' ||
      !/^[A-Za-z0-9.-]{1,255}$/u.test(item.name) ||
      item.name === '.' ||
      item.name === '..' ||
      typeof item.title !== 'string' ||
      item.title.trim() === '' ||
      !item.title.isWellFormed() ||
      new TextEncoder().encode(item.title).byteLength > 255 ||
      /[\p{Cc}\p{Cf}]/u.test(item.title)
    ) {
      throw new RememberMeError('unavailable');
    }
    flow = Object.freeze({ name: item.name, title: item.title });
  }
  return {
    accessToken: body.accessToken,
    expiresAt: time(body.expiresAt),
    scope: Object.freeze({ ...scope }),
    principal: body.principal,
    environment: body.environment,
    terminalAvailable: body.terminalAvailable as boolean,
    keepAlive: keepAlivePolicy(body.keepAlive),
    ...(flow ? { flow } : {}),
  };
}

async function startProof(
  http: Http,
  handle: BrowserBinding,
  purpose: ProofPurpose,
  accessToken?: string,
  signal?: AbortSignal,
): Promise<{ challenge: string; attemptToken: string }> {
  const binding = handle.binding;
  if (purpose !== 'enroll' && binding === null) {
    throw new RememberMeError('outcome-unknown');
  }
  const fields: Record<string, string> =
    purpose === 'enroll' ? { publicKey: await handle.publicKey() } : { ...binding };
  const body = object(await http.post(`remember/${purpose}`, fields, accessToken, 202, signal), [
    'status',
    'attemptToken',
    'challenge',
    'expiresAt',
  ]);
  if (
    body.status !== 'proof-required' ||
    !isToken(body.attemptToken, 'bwr1.') ||
    typeof body.challenge !== 'string'
  ) {
    throw new RememberMeError('unavailable');
  }
  time(body.expiresAt);
  return { challenge: body.challenge, attemptToken: body.attemptToken };
}

async function revoke(http: Http, handle: BrowserBinding, signal?: AbortSignal): Promise<void> {
  if (handle.binding === null) {
    throw new RememberMeError('outcome-unknown');
  }
  const start = await startProof(http, handle, 'revoke', undefined, signal);
  const signature = await handle.sign(start.challenge, 'revoke');
  await http.post('remember/prove', { signature }, start.attemptToken, 204, signal);
}

// This object is an opaque, tab-memory permission, not serializable bearer state.
// Keep one per authenticated UI/execution; a new login does not dispose an old
// execution or implicitly log out unrelated grants/bindings.
export class WebAccess {
  readonly #http: Http;
  #managementHttp: Pick<Http, 'post' | 'artifactImage'>;
  #managementChannel: ManagementConnection | null = null;
  #managementAttempted = false;
  #response: AccessResponse;
  #forgotten = false;
  #closed = false;
  readonly #statusListeners = new Set<() => void>();
  readonly #resetCleanups = new Set<() => void>();
  #binding: BrowserBinding | null;
  #enrollment: {
    handle: BrowserBinding | null;
    controller: AbortController;
    done: Promise<void>;
  } | null = null;
  #logout: Promise<LogoutResult> | null = null;
  #artifact: { controller: AbortController; done: Promise<ReceivedArtifact> } | null = null;

  constructor(http: Http, response: AccessResponse, binding: BrowserBinding | null) {
    this.#http = http;
    this.#managementHttp = http;
    this.#response = response;
    this.#binding = binding;
  }

  snapshot(): AccessSnapshot {
    const { scope, principal, expiresAt, environment, terminalAvailable, keepAlive, flow } =
      this.#response;
    return Object.freeze({
      scope,
      principal,
      expiresAt,
      environment,
      terminalAvailable,
      ...(keepAlive ? { keepAlive } : {}),
      ...(flow ? { flow } : {}),
    });
  }
  toJSON(): AccessSnapshot {
    return this.snapshot();
  }

  // Local web-grant lifetime only, not the server session or a running shell.
  // An individual operation being denied does not close/revoke this access.
  status(): AccessStatus {
    if (this.#closed) {
      return 'closed';
    }
    return Date.now() >= Date.parse(this.#response.expiresAt) ? 'expired' : 'active';
  }

  subscribeStatus(listener: () => void): () => void {
    this.#statusListeners.add(listener);
    return () => {
      this.#statusListeners.delete(listener);
    };
  }
  registerResetCleanup(cleanup: () => void): () => void {
    this.#resetCleanups.add(cleanup);
    return () => this.#resetCleanups.delete(cleanup);
  }

  managementStatus(): AccessStatus {
    if (this.#closed) {
      return 'closed';
    }
    if (this.#managementChannel !== null) {
      return this.#managementChannel.connected()
        ? 'active'
        : this.#managementChannel.available()
          ? this.status()
          : 'closed';
    }
    return this.#managementAttempted ? 'closed' : this.status();
  }
  managementToken(): string {
    this.#managementAllowed();
    if (this.status() !== 'active') {
      throw new RememberMeError('denied');
    }
    return this.#response.accessToken;
  }
  openManagement(
    changed: (state: TerminalState) => void,
    options: { keepAlive?: string } = {},
    factory?: SocketFactory,
  ): ManagementConnection {
    this.#managementAllowed();
    if (this.#managementAttempted) {
      throw new RememberMeError('busy');
    }
    this.#managementAttempted = true;
    const channel = new ManagementConnection(
      this,
      (state) => {
        changed(state);
        for (const listener of [...this.#statusListeners]) {
          try {
            listener();
          } catch {
            console.error('[Bifröst/access-status]', 'listener-failed');
          }
        }
      },
      factory,
      options,
    );
    this.#managementChannel = channel;
    this.#managementHttp = {
      post: (action, fields, _token, status, signal) =>
        channel.post(action, fields, status, signal),
      artifactImage: (request, _token, signal) => channel.artifactImage(request, signal),
    };
    return channel;
  }

  terminalToken(): string {
    if (
      this.#closed ||
      !this.#response.terminalAvailable ||
      Date.now() >= Date.parse(this.#response.expiresAt)
    ) {
      throw new RememberMeError('denied');
    }
    return this.#response.accessToken; // Only the terminal wire adapter should consume this value.
  }

  #managementAllowed() {
    if (
      this.#closed ||
      this.#response.environment !== 'management' ||
      (this.#managementChannel === null
        ? this.#managementAttempted || Date.now() >= Date.parse(this.#response.expiresAt)
        : !this.#managementChannel.available())
    ) {
      throw new RememberMeError('denied');
    }
  }

  async downloadArtifact(
    request: ArtifactRequest,
    signal?: AbortSignal,
  ): Promise<ReceivedArtifact> {
    this.#managementAllowed();
    const selected = Object.freeze({ ...request }) as ArtifactRequest;
    artifactFields(selected);
    if (this.#artifact !== null) {
      throw new RememberMeError('busy');
    }
    const controller = new AbortController();
    const stopped =
      signal === undefined ? controller.signal : AbortSignal.any([signal, controller.signal]);
    const operation = {
      controller,
      done: (async () => {
        const result = await receiveArtifact(
          selected,
          (receiving) =>
            this.#managementHttp.artifactImage(selected, this.#response.accessToken, receiving),
          stopped,
        );
        if (this.#closed) {
          throw new RememberMeError('denied');
        }
        return result;
      })(),
    };
    this.#artifact = operation;
    try {
      return await operation.done;
    } finally {
      if (this.#artifact === operation) {
        this.#artifact = null;
      }
    }
  }
  async managementVersion(long = true, signal?: AbortSignal): Promise<VersionInfo> {
    this.#managementAllowed();
    if (typeof long !== 'boolean') {
      throw new RememberMeError('unavailable');
    }
    const result = versionInfo(
      await this.#managementHttp.post(
        'management/version/show',
        { long: String(long) },
        this.#response.accessToken,
        200,
        signal,
      ),
      long,
    );
    if (this.#closed) {
      throw new RememberMeError('denied');
    }
    return result;
  }
  async managementFlows(
    options: PageOptions = {},
    signal?: AbortSignal,
  ): Promise<Page<FlowSummary>> {
    this.#managementAllowed();
    const fields = pageFields(options);
    const result = page<FlowSummary>(
      await this.#managementHttp.post(
        'management/flows/list',
        fields,
        this.#response.accessToken,
        200,
        signal,
      ),
      'flows',
      Number(fields.limit),
    );
    if (this.#closed) {
      throw new RememberMeError('denied');
    }
    return result;
  }
  async managementSessions(
    options: SessionOptions = {},
    signal?: AbortSignal,
  ): Promise<Page<SessionItem>> {
    this.#managementAllowed();
    const fields = sessionFields(options);
    const result = page<SessionItem>(
      await this.#managementHttp.post(
        'management/sessions/list',
        fields,
        this.#response.accessToken,
        200,
        signal,
      ),
      'sessions',
      Number(fields.limit),
    );
    if (this.#closed) {
      throw new RememberMeError('denied');
    }
    return result;
  }
  async managementAuditlogs(
    options: PageOptions = {},
    signal?: AbortSignal,
  ): Promise<Page<AuditlogSummary>> {
    this.#managementAllowed();
    const fields = pageFields(options);
    const result = page<AuditlogSummary>(
      await this.#managementHttp.post(
        'management/auditlogs/list',
        fields,
        this.#response.accessToken,
        200,
        signal,
      ),
      'auditlogs',
      Number(fields.limit),
    );
    if (this.#closed) {
      throw new RememberMeError('denied');
    }
    if (
      result.items.some(
        (row, index) =>
          index > 0 &&
          (fields.sort === 'name-desc'
            ? row.name >= (result.items[index - 1]?.name ?? '')
            : row.name <= (result.items[index - 1]?.name ?? '')),
      ) ||
      (result.next !== '' && (result.items.length === 0 || result.next === fields.after))
    ) {
      throw new RememberMeError('unavailable');
    }
    return result;
  }
  async managementRecordings(
    auditlog: string,
    options: RecordingOptions = {},
    signal?: AbortSignal,
  ): Promise<Page<RecordingSummary>> {
    this.#managementAllowed();
    const fields: Record<string, string> = {
      ...recordingFields(options),
      auditlog: auditlogName(auditlog),
    };
    const result = page<RecordingSummary>(
      await this.#managementHttp.post(
        'management/recordings/list',
        fields,
        this.#response.accessToken,
        200,
        signal,
      ),
      'recordings',
      Number(fields.limit),
    );
    if (this.#closed) {
      throw new RememberMeError('denied');
    }
    const startKey = (value: string) =>
      `${value.slice(0, 19)}.${value.slice(19, -1).replace('.', '').padEnd(9, '0')}`;
    if (
      new Set(result.items.map((row) => row.id)).size !== result.items.length ||
      result.items.some((row, index) => {
        const previous = result.items[index - 1];
        const at = startKey(row.startedAt);
        return (
          row.auditlog !== fields.auditlog ||
          (fields.flow !== '' && row.flow !== fields.flow) ||
          (fields.user !== '' && row.user !== fields.user) ||
          (fields.target !== '' && row.target !== fields.target) ||
          (fields.status !== 'all' && row.status !== fields.status) ||
          (fields.startedFrom !== '' && at < startKey(fields.startedFrom ?? '')) ||
          (fields.startedUntil !== '' && at > startKey(fields.startedUntil ?? '')) ||
          (previous !== undefined &&
            ((fields.sort === 'started-asc'
              ? at < startKey(previous.startedAt)
              : at > startKey(previous.startedAt)) ||
              (at === startKey(previous.startedAt) && row.id <= previous.id)))
        );
      }) ||
      (result.next !== '' && (result.items.length === 0 || result.next === fields.after))
    ) {
      throw new RememberMeError('unavailable');
    }
    return result;
  }
  async managementSession(flow: string, id: string, signal?: AbortSignal): Promise<SessionItem> {
    this.#managementAllowed();
    if (
      typeof flow !== 'string' ||
      !flow.isWellFormed() ||
      new TextEncoder().encode(flow).length > 255 ||
      /[\p{Cc}]/u.test(flow) ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(id)
    ) {
      throw new RememberMeError('unavailable');
    }
    const result = detail(
      await this.#managementHttp.post(
        'management/sessions/show',
        { flow, id },
        this.#response.accessToken,
        200,
        signal,
      ),
    );
    if (this.#closed || result.flow !== flow || result.id !== id) {
      throw new RememberMeError('denied');
    }
    return result;
  }

  async prepareSessionAction(
    action: SessionAction,
    flow: string,
    id: string,
    signal?: AbortSignal,
  ): Promise<SessionActionConfirmation> {
    this.#managementAllowed();
    if (
      !['disconnect', 'dispose'].includes(action) ||
      typeof flow !== 'string' ||
      !flow.isWellFormed() ||
      new TextEncoder().encode(flow).length > 255 ||
      /[\p{Cc}]/u.test(flow) ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(id)
    ) {
      throw new RememberMeError('unavailable');
    }
    const prepared = actionPreparation(
      await this.#managementHttp.post(
        'management/sessions/prepare',
        { action, flow, id },
        this.#response.accessToken,
        202,
        signal,
      ),
      action,
      flow,
      id,
    );
    const handle = new SessionActionConfirmation(
      prepared.preview,
      async (stopped) => {
        this.#managementAllowed();
        const result = actionResult(
          await this.#managementHttp.post(
            'management/sessions/confirm',
            { confirmationToken: prepared.confirmationToken },
            this.#response.accessToken,
            200,
            stopped,
          ),
          prepared.preview,
        );
        if (this.#closed) {
          throw new RememberMeError('denied');
        }
        return result;
      },
      async () => {
        this.#managementAllowed();
        await this.#managementHttp.post(
          'management/sessions/cancel',
          { confirmationToken: prepared.confirmationToken },
          this.#response.accessToken,
          204,
        );
      },
    );
    if (this.#closed || signal?.aborted) {
      await handle.cancel();
      throw new RememberMeError('cancelled');
    }
    return handle;
  }

  async remember(options: { explicitOptIn: boolean }, signal?: AbortSignal): Promise<void> {
    if (options?.explicitOptIn !== true) {
      throw new RememberMeError('opt-in-required');
    }
    if (this.#closed) {
      throw new RememberMeError('denied');
    }
    if (this.#enrollment !== null) {
      throw new RememberMeError('busy');
    }
    if (this.#binding !== null) {
      throw new RememberMeError(
        this.#binding.binding === null ? 'outcome-unknown' : 'already-remembered',
      );
    }
    const controller = new AbortController();
    const stopped =
      signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal]);
    const operation = {
      handle: null as BrowserBinding | null,
      controller,
      done: Promise.resolve(),
    };
    this.#enrollment = operation;
    operation.done = this.#enroll(operation, stopped);
    try {
      await operation.done;
    } finally {
      if (this.#enrollment === operation) {
        this.#enrollment = null;
      }
    }
  }

  async #enroll(operation: { handle: BrowserBinding | null }, signal: AbortSignal): Promise<void> {
    let proving = false;
    try {
      if (signal.aborted) {
        throw new RememberMeError('cancelled');
      }
      if ((await BrowserBinding.load(this.#response.scope)) !== null) {
        throw new RememberMeError('already-remembered');
      }
      operation.handle = await BrowserBinding.prepare(this.#response.scope, {
        explicitOptIn: true,
      });
      this.#binding = operation.handle; // Retain ownership even if the claim response is lost.
      if (signal.aborted) {
        throw new RememberMeError('cancelled');
      }
      const start = await startProof(
        this.#http,
        operation.handle,
        'enroll',
        this.#response.accessToken,
        signal,
      );
      const signature = await operation.handle.sign(start.challenge, 'enroll');
      if (signal.aborted) {
        throw new RememberMeError('cancelled');
      }
      proving = true; // Any subsequent failure may have committed a server binding.
      const response = object(
        await this.#http.post('remember/prove', { signature }, start.attemptToken, 201, signal),
        ['status', 'flow', 'sessionId', 'bindingId', 'expiresAt'],
      );
      if (response.status !== 'remembered') {
        throw new RememberMeError('unavailable');
      }
      time(response.expiresAt);
      const binding: Binding = {
        flow: response.flow as string,
        sessionId: response.sessionId as string,
        bindingId: response.bindingId as string,
      };
      validateBinding(binding);
      // sign() already checked this exact original challenge. Enrollment replies
      // must name its flow/session, not an unrelated selector from a response.
      const challengePayload = new TextDecoder()
        .decode(decode64(start.challenge, 16 << 10))
        .split('\0')[1];
      if (challengePayload === undefined) {
        throw new RememberMeError('unavailable');
      }
      const challenge = JSON.parse(challengePayload) as Record<string, unknown>;
      if (challenge.flow !== binding.flow || challenge.sessionId !== binding.sessionId) {
        throw new RememberMeError('unavailable');
      }
      if (signal.aborted || this.#closed) {
        throw new RememberMeError('cancelled');
      }
      operation.handle = await operation.handle.complete(binding);
      this.#binding = operation.handle;
      if (signal.aborted || this.#closed) {
        throw new RememberMeError('cancelled');
      }
    } catch (error) {
      if (!proving && operation.handle !== null) {
        try {
          await operation.handle.forgetLocal();
          if (this.#binding === operation.handle) {
            this.#binding = null;
          }
        } catch {
          /* Preserve newer/corrupt state for explicit recovery, never overwrite it. */
        }
      }
      if (proving) {
        throw new RememberMeError('outcome-unknown'); // No replay/automatic logout or destructive rollback.
      }
      throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
    }
  }

  // Stop new use immediately. Server logout is authoritative, including while
  // enrollment is signing/committing; parent closure prevents late enrollment.
  // On failure keep local keys/selectors for explicit retry, never claim logout.
  async logout(signal?: AbortSignal): Promise<LogoutResult> {
    if (this.#forgotten) {
      throw new RememberMeError('denied');
    }
    if (this.#logout !== null) {
      return this.#logout;
    }
    let complete!: (result: LogoutResult) => void;
    let fail!: (error: unknown) => void;
    const shared = new Promise<LogoutResult>((resolve, reject) => {
      complete = resolve;
      fail = reject;
    });
    // Establish the shared operation before any observer or abort callback can
    // reenter. Observation must never replace authoritative logout/cleanup.
    this.#logout = shared;
    this.#closed = true;
    const enrollment = this.#enrollment;
    enrollment?.controller.abort();
    const artifact = this.#artifact;
    artifact?.controller.abort();
    const operation = (async () => {
      let failed: unknown;
      try {
        await this.#http.post('logout', {}, this.#response.accessToken, 204, signal);
      } catch (error) {
        failed = error;
      } finally {
        this.#managementChannel?.disconnect();
      }
      await enrollment?.done.catch(() => undefined);
      await artifact?.done.catch(() => undefined);
      const handle = this.#binding ?? enrollment?.handle;
      if (failed !== undefined) {
        // A grant with no active children may already have been pruned. Prove
        // ownership of ONLY this access's own binding, never one loaded from a
        // different regular login/actor in this browser's IndexedDB.
        if (
          failed instanceof RememberMeError &&
          failed.code === 'denied' &&
          handle?.binding !== null &&
          handle?.binding !== undefined
        ) {
          await revoke(this.#http, handle, signal);
        } else {
          throw failed;
        }
      }
      return forgetOwned(handle);
    })();
    void operation.then(complete, fail);
    for (const listener of [...this.#statusListeners]) {
      try {
        listener();
      } catch {
        // A subscriber may hold arbitrary private data in its error. Report
        // only the fixed diagnostic; cleanup and other observers still run.
        console.error('[Bifröst/access-status]', 'listener-failed');
      }
    }
    try {
      return await shared;
    } catch (error) {
      this.#logout = null;
      throw error;
    }
  }
  rememberedBindingForReset(): Binding | null {
    return this.#binding?.binding ?? null;
  }
  // Explicit profile reset may discard local capabilities even when remote
  // logout was not confirmed. Ordinary logout keeps its existing failure path.
  async retireForReset(): Promise<void> {
    this.#closed = true;
    this.#response = Object.freeze({ ...this.#response, accessToken: '' });
    this.#forgotten = true;
    const enrollment = this.#enrollment;
    const artifact = this.#artifact;
    enrollment?.controller.abort();
    artifact?.controller.abort();
    let failed = false;
    for (const cleanup of [...this.#resetCleanups]) {
      try {
        cleanup();
      } catch {
        failed = true;
      }
    }
    this.#resetCleanups.clear();
    try {
      this.#managementChannel?.disconnect();
    } catch {
      failed = true;
    }
    for (const listener of [...this.#statusListeners]) {
      try {
        listener();
      } catch {
        console.error('[Bifröst/access-status]', 'listener-failed');
      }
    }
    await Promise.allSettled([enrollment?.done, artifact?.done, this.#logout]);
    this.#binding = null;
    this.#enrollment = null;
    this.#response = Object.freeze({ ...this.#response, accessToken: '' });
    this.#forgotten = true;
    if (failed) {
      throw new RememberMeError('unavailable');
    }
  }
}

export class BrowserClient {
  readonly #scope: Scope;
  readonly #http: Http;
  #loginActive = false;
  constructor(scope: Scope, transport?: Transport) {
    this.#http = new Http(scope, transport);
    this.#scope = Object.freeze({ ...scope });
  }

  async password(user: string, password: string, signal?: AbortSignal): Promise<WebAccess> {
    const encoder = new TextEncoder();
    if (
      typeof user !== 'string' ||
      !user.isWellFormed() ||
      encoder.encode(user).byteLength > 256 ||
      /[\p{Cc}]/u.test(user) ||
      typeof password !== 'string' ||
      !password.isWellFormed() ||
      encoder.encode(password).byteLength > 4096
    ) {
      throw new RememberMeError('unavailable');
    }
    const response = accessResponse(
      await this.#http.post('login/password', { user, password }, undefined, 200, signal),
      this.#scope,
    );
    if (signal?.aborted) {
      throw new RememberMeError('cancelled');
    }
    return new WebAccess(this.#http, response, null);
  }

  async interactive(user: string, handler: StepHandler, signal?: AbortSignal): Promise<WebAccess> {
    if (this.#loginActive) {
      throw new RememberMeError('busy');
    }
    if (
      typeof user !== 'string' ||
      !user.isWellFormed() ||
      new TextEncoder().encode(user).byteLength > 256 ||
      /[\p{Cc}]/u.test(user)
    ) {
      throw new RememberMeError('unavailable');
    }
    this.#loginActive = true;
    try {
      const value = await interactive(this.#http, user, handler, signal);
      if (signal?.aborted) {
        throw new RememberMeError('cancelled');
      }
      try {
        return new WebAccess(this.#http, accessResponse(value, this.#scope), null);
      } catch {
        throw new RememberMeError('login-unknown');
      }
    } finally {
      this.#loginActive = false;
    }
  }

  async publicKey(user: string, key: LoginKey, signal?: AbortSignal): Promise<WebAccess> {
    if (this.#loginActive) {
      throw new RememberMeError('busy');
    }
    if (
      typeof user !== 'string' ||
      !user.isWellFormed() ||
      new TextEncoder().encode(user).byteLength > 256 ||
      /[\p{Cc}]/u.test(user)
    ) {
      throw new RememberMeError('unavailable');
    }
    this.#loginActive = true;
    try {
      const value = await publicKeyLogin(this.#http, this.#scope, user, key, signal);
      if (signal?.aborted) {
        throw new RememberMeError('cancelled');
      }
      try {
        return new WebAccess(this.#http, accessResponse(value, this.#scope), null);
      } catch {
        throw new RememberMeError('login-unknown');
      }
    } finally {
      this.#loginActive = false;
    }
  }

  async resume(signal?: AbortSignal): Promise<WebAccess | null> {
    if (signal?.aborted) {
      throw new RememberMeError('cancelled');
    }
    const handle = await BrowserBinding.load(this.#scope);
    if (handle === null) {
      return null;
    }
    if (handle.binding === null) {
      throw new RememberMeError('outcome-unknown');
    }
    const start = await startProof(this.#http, handle, 'resume', undefined, signal);
    const signature = await handle.sign(start.challenge, 'resume');
    const response = accessResponse(
      await this.#http.post('remember/prove', { signature }, start.attemptToken, 200, signal),
      this.#scope,
    );
    if (signal?.aborted) {
      throw new RememberMeError('cancelled');
    }
    return new WebAccess(this.#http, response, handle);
  }

  async forgetRemembered(signal?: AbortSignal): Promise<LogoutResult> {
    const handle = await BrowserBinding.load(this.#scope);
    if (handle === null) {
      return { localState: 'not-owned' };
    }
    return this.revokeSelection(handle, signal);
  }

  // A confirmation dialog must retain the selected handle, not silently adopt
  // another tab's newer registration between showing the dialog and confirming.
  async revokeSelection(handle: BrowserBinding, signal?: AbortSignal): Promise<LogoutResult> {
    if (handle.scope.origin !== this.#scope.origin || handle.scope.slug !== this.#scope.slug) {
      throw new RememberMeError('changed');
    }
    await revoke(this.#http, handle, signal);
    return forgetOwned(handle); // CAS protects a newer enrollment in another tab.
  }
}
