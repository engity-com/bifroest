import CancelIcon from '@mui/icons-material/Cancel';
import { IconButton, Tooltip } from '@mui/material';
import {
  type Ref,
  useEffect,
  useEffectEvent,
  useId,
  useImperativeHandle,
  useRef,
  useState,
} from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { RecordingSummary } from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { useAdminDetail } from '../ui/admin-navigation';
import { reportUiError } from '../ui/error-report';
import { VerificationResultButton } from '../ui/GridWork';
import { LicenseIcon } from '../ui/LicenseIcon';
import { relationFlow } from '../ui/ManagementJump';
import type { ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import {
  Alert,
  Button,
  Checkbox,
  Modal,
  PasswordInput,
  Select,
  TextInput,
  useComputedColorScheme,
} from '../ui/material';
import { type Message, t } from '../ui/messages';
import { profileResetEvent } from '../ui/profile-reset';
import { ReadProgress } from '../ui/ReadProgress';
import { readLocalBytes } from '../wasm/local-file';
import { ArtifactCatalog } from './ArtifactCatalog';
import { ArtifactOpenByID } from './ArtifactOpenByID';
import { ArtifactSourceDetails } from './ArtifactSourceDetails';
import { AuditCatalog } from './AuditCatalog';
import { AuditEvents } from './AuditEvents';
import { useAuditView } from './AuditViewContext';
import { AuditWorkspace } from './AuditWorkspace';
import { type AuditEventIndex, type AuditEventRow, indexAuditEvents } from './audit-events';
import {
  EvidenceError,
  type EvidenceMetadata,
  evidenceOptions,
  type VerifiedArtifact,
} from './evidence-protocol';
import { LocalArtifactDownload } from './local-download';
import { inspectProtection } from './protection';
import { type ArtifactRequest, artifactFields, type ReceivedArtifact } from './protocol';
import { RecordingPlayer } from './RecordingPlayer';
import { verifiedRecordingContext } from './recording-flow';
import { useArtifactSecrets } from './session-secrets';
import { VerificationDialog } from './VerificationDialog';
import { type EvidenceKey, verifyArtifact } from './verify';
import './recording-player.css';

type Phase = 'downloading' | 'inspecting' | 'verifying';
export interface ArtifactPanelProps {
  access: WebAccess;
  disabled: boolean;
  remoteDisabled?: boolean;
  active?: boolean;
  view?: 'recordings' | 'auditlogs';
}
export interface ArtifactEvidencePanelProps extends ArtifactPanelProps {
  backgroundAllowed?: boolean;
  verificationCancel?: number;
  onPhaseChange?: (phase: Phase | null) => void;
  regionLabel?: string;
  hideBreadcrumbs?: boolean;
  controlRef?: Ref<ArtifactEvidenceControl>;
  onEvidenceState?: (state: ArtifactEvidenceState) => void;
  onResultReady?: () => void;
}
export interface ArtifactEvidenceControl {
  openOptions(): void;
  cancel(): void;
  showDetails(): void;
}
export interface ArtifactEvidenceState {
  phase: Phase | null;
  progress: Progress | null;
  hasGrid: boolean;
  received: boolean;
  status: string | undefined;
  result?: 'success' | 'failure' | undefined;
}
type UsedExpectation = { enabled: boolean; producer: string; source: 'reported' | 'user' };
function failure(error: unknown): Message {
  if (error instanceof EvidenceError) {
    return error.code === 'key'
      ? 'artifactKeyFailed'
      : error.code === 'verification'
        ? 'artifactVerificationFailed'
        : error.code === 'limit'
          ? 'artifactLimit'
          : error.code === 'cancelled'
            ? 'artifactCancelled'
            : error.code === 'input'
              ? 'artifactInputFailed'
              : 'artifactUnavailable';
  }
  return error instanceof RememberMeError && error.code === 'denied'
    ? 'artifactDownloadDenied'
    : error instanceof RememberMeError && error.code === 'cancelled'
      ? 'artifactCancelled'
      : 'artifactDownloadFailed';
}

// Both pages use the same actor-owned, volatile key cache, never each other's
// selection, workers, verification result or plaintext. No form uploads secrets.
export function ArtifactPanel(props: ArtifactPanelProps) {
  return props.view === 'auditlogs' ? (
    <AuditWorkspace {...props} Evidence={ArtifactEvidencePanel} />
  ) : (
    <ArtifactEvidencePanel {...props} />
  );
}

export function ArtifactEvidencePanel({
  access,
  disabled,
  remoteDisabled = false,
  active = true,
  view = 'recordings',
  backgroundAllowed = false,
  verificationCancel = 0,
  onPhaseChange,
  regionLabel,
  hideBreadcrumbs = false,
  controlRef,
  onEvidenceState,
  onResultReady,
}: ArtifactEvidencePanelProps) {
  const palette = useComputedColorScheme('light');
  const auditView = useAuditView();
  const managed = !!controlRef;
  const secrets = useArtifactSecrets(access);
  const navigation = useManagementNavigation();
  const route = navigation?.location.page === view ? navigation.location : null;
  const routeRef = useRef(route);
  if (route !== null) {
    routeRef.current = route;
  }
  const activeRef = useRef(active);
  activeRef.current = active;
  const ownerRef = useRef(access);
  ownerRef.current = access;
  const consumedRoute = useRef<string | null>(null);
  const consumedSelection = useRef<string | null>(null);
  const returnRoute = useRef<ManagementLocation | null>(null);
  const routeKey = JSON.stringify(route);
  const routedSummary = useRef<RecordingSummary | null>(null);
  const [recordingFlow, setRecordingFlow] = useState('');
  const [recordingSession, setRecordingSession] = useState('');
  const [auditEvent, setAuditEvent] = useState<AuditEventRow | null>(null);
  const inputID = useId();
  const passwordID = useId();
  const [opened, setOpened] = useState<ArtifactRequest | null>(null);
  const [selection, setSelection] = useState<RecordingSummary | null>(null);
  const [received, setReceived] = useState<ReceivedArtifact | null>(null);
  const [protection, setProtection] = useState<EvidenceMetadata | null>(null);
  const [verified, setVerified] = useState<VerifiedArtifact | null>(null);
  const [verifiedSensitive, setVerifiedSensitive] = useState(false);
  const [auditIndex, setAuditIndex] = useState<AuditEventIndex | null>(null);
  const [phase, setPhase] = useState<Phase | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  useEffect(() => {
    onPhaseChange?.(phase);
  }, [onPhaseChange, phase]);
  const [notice, setNotice] = useState<Message | null>(null);
  const [errorCode, setErrorCode] = useState('');
  const [failedStage, setFailedStage] = useState<Phase | null>(null);
  const [details, setDetails] = useState(false);
  const [filePage, setFilePage] = useState(0);
  const [candidate, setCandidate] = useState(false);
  const [keyRevision, setKeyRevision] = useState(0);
  const [cacheRevision, setCacheRevision] = useState(0);
  const [validateIdentity, setValidateIdentity] = useState(false);
  const [producer, setProducer] = useState('');
  const [producerSource, setProducerSource] = useState<'reported' | 'user'>('reported');
  const [used, setUsed] = useState<UsedExpectation | null>(null);
  const [sensitive, setSensitive] = useState(false);
  const [level, setLevel] = useState<'outer' | 'private'>('private');
  const [scope, setScope] = useState<'complete' | 'captured-prefix'>('complete');
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [verificationInput, setVerificationInput] = useState<'fresh' | 'received'>('fresh');
  const effectiveSensitive = auditView?.sensitive ?? sensitive;
  const [auditlog, setAuditlog] = useState('');
  const [id, setID] = useState('');
  const heading = useRef<HTMLDivElement | null>(null);
  const keyInput = useRef<HTMLInputElement | null>(null);
  const form = useRef<HTMLFormElement | null>(null);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const downloads = useRef(new LocalArtifactDownload());
  const forgetEvidence = useEffectEvent(() => {
    setOptionsOpen(false);
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    downloads.current.clear();
    clearInputs();
    setOpened(null);
    setSelection(null);
    setReceived(null);
    setProtection(null);
    setVerified(null);
    setPhase(null);
    setNotice(null);
    setDetails(false);
    setUsed(null);
    setAuditEvent(null);
    setRecordingFlow('');
    setProducer('');
    setValidateIdentity(false);
    setSensitive(false);
    setAuditlog('');
    setID('');
    routedSummary.current = null;
  });
  useEffect(() => {
    const forget = () => forgetEvidence();
    window.addEventListener(profileResetEvent, forget);
    return () => window.removeEventListener(profileResetEvent, forget);
  }, []);
  const identity = () => ({ enabled: validateIdentity, producer, source: producerSource });
  const clearInputs = () => {
    if (keyInput.current) {
      keyInput.current.value = '';
    }
    const input = form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]');
    if (input) {
      input.value = '';
    }
    setCandidate(false);
    setKeyRevision((value) => value + 1);
  };
  const cancelFromOutside = useEffectEvent(() => {
    operation.current?.abort();
    clearInputs();
    if (operation.current !== null) {
      setNotice('artifactCancelled');
    }
  });
  const consumedCancel = useRef(verificationCancel);
  useEffect(() => {
    if (consumedCancel.current !== verificationCancel) {
      consumedCancel.current = verificationCancel;
      cancelFromOutside();
    }
  }, [verificationCancel]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Actor/page/availability boundaries retire local output and unvalidated input, never a replacement login.
  useEffect(() => {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    downloads.current.clear();
    setOpened(null);
    setSelection(null);
    setRecordingFlow('');
    consumedRoute.current = null;
    consumedSelection.current = null;
    returnRoute.current = null;
    routedSummary.current = null;
    setAuditEvent(null);
    setReceived(null);
    setProtection(null);
    setVerified(null);
    setPhase(null);
    setNotice(null);
    setDetails(false);
    setUsed(null);
    setValidateIdentity(false);
    setProducer('');
    setProducerSource('reported');
    setOptionsOpen(false);
    setSensitive(false);
    setLevel('private');
    setScope('complete');
    setAuditlog('');
    setID('');
    clearInputs();
    return () => {
      generation.current++;
      operation.current?.abort();
      operation.current = null;
      downloads.current.clear();
    };
  }, [access, disabled, view]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Hide portals and clear unvalidated inputs on deactivation; retain the explicitly approved tab key cache.
  useEffect(() => {
    if (!active) {
      setOptionsOpen(false);
      if (!backgroundAllowed) {
        operation.current?.abort();
      }
      clearInputs();
      setDetails(false);
    }
  }, [active, backgroundAllowed]);
  const current = (token: number, signal: AbortSignal) =>
    token === generation.current &&
    !signal.aborted &&
    access.status() !== 'closed' &&
    ownerRef.current === access;
  function matchesRoute(request: ArtifactRequest): boolean {
    const target = routeRef.current;
    if (!target) {
      return navigation === null;
    }
    if (request.kind === 'audit') {
      return target.page === 'auditlogs' && target.auditlog === request.auditlog;
    }
    return (
      target.page === 'recordings' &&
      (target.id ?? target.recordingHint) === request.id &&
      target.auditlogHint === request.auditlog
    );
  }
  async function run(
    next: Phase,
    action: (signal: AbortSignal, token: number, stage: (phase: Phase) => void) => Promise<void>,
  ) {
    if (disabled || operation.current !== null) {
      return;
    }
    const controller = new AbortController();
    const token = ++generation.current;
    operation.current = controller;
    let stage = next;
    setPhase(next);
    setProgress(null);
    setNotice(null);
    setErrorCode('');
    setFailedStage(null);
    try {
      await action(controller.signal, token, (value) => {
        stage = value;
        if (current(token, controller.signal)) {
          setPhase(value);
        }
      });
    } catch (error) {
      if (token === generation.current) {
        reportUiError('artifact', error);
        setNotice(failure(error));
        setFailedStage(stage);
        setErrorCode(
          error instanceof EvidenceError || error instanceof RememberMeError
            ? error.code
            : 'unavailable',
        );
      }
    } finally {
      clearInputs();
      if (operation.current === controller) {
        operation.current = null;
        setPhase(null);
      }
    }
  }
  function resetResult() {
    setAuditIndex(null);
    setVerifiedSensitive(false);
    setAuditEvent(null);
    downloads.current.clear();
    setVerified(null);
    setUsed(null);
    setNotice(null);
  }
  async function check(
    image: ReceivedArtifact,
    header: EvidenceMetadata,
    key: EvidenceKey | null,
    expectation: UsedExpectation,
    signal: AbortSignal,
    token: number,
    includeSensitive = effectiveSensitive,
  ) {
    const checked = {
      ...expectation,
      producer: expectation.enabled
        ? expectation.source === 'user'
          ? expectation.producer
          : header.producer
        : '',
    };
    if (current(token, signal) && !(managed && auditView?.local)) {
      setUsed(checked);
    }
    const options = evidenceOptions(image.request, {
      producer: checked.producer,
      allowUntrusted: !expectation.enabled,
      recipient: level === 'outer' ? header.expectedRecipient : '',
      ...(level === 'private' && header.expectedRecipient !== '' ? { recipientFromKey: true } : {}),
      level,
      export: level === 'private',
      sensitive: level === 'private' && image.request.kind === 'audit' && includeSensitive,
      auditScope: image.request.kind === 'audit' ? scope : '',
    });
    const result = await verifyArtifact(image, options, key, signal, (value) => {
      if (current(token, signal)) {
        setProgress(value);
      }
    });
    if (!current(token, signal)) {
      return;
    }
    if (!matchesRoute(image.request)) {
      throw new EvidenceError('cancelled');
    }
    const preparedIndex =
      managed &&
      image.request.kind === 'audit' &&
      result.output &&
      result.metadata.outputFormat === 'jsonl'
        ? await indexAuditEvents(result.output, signal, (value) => {
            if (current(token, signal)) {
              setProgress(value);
            }
          })
        : null;
    if (!current(token, signal)) {
      return;
    }
    const context = await verifiedRecordingContext(result);
    const flow = context.flow;
    if (!current(token, signal)) {
      return;
    }
    const target = routeRef.current;
    if (image.request.kind === 'recording' && target?.flow && flow && target.flow !== flow) {
      throw new EvidenceError('verification');
    }
    if (
      image.request.kind === 'recording' &&
      result.metadata.validation === 'private' &&
      target?.sessionId &&
      context.sessionId !== target.sessionId
    ) {
      throw new EvidenceError('verification');
    }
    setRecordingFlow(flow);
    setRecordingSession(context.sessionId);
    if (key !== null) {
      secrets.remember(key, result);
      setCacheRevision((value) => value + 1);
    }
    resetResult();
    setVerified(result);
    setAuditIndex(preparedIndex);
    setVerifiedSensitive(includeSensitive);
    setUsed(checked);
    clearInputs();
    if (
      managed &&
      image.request.kind === 'audit' &&
      result.output &&
      result.metadata.outputFormat === 'jsonl'
    ) {
      onResultReady?.();
    }
    if (
      image.request.kind === 'recording' &&
      relationFlow(flow) &&
      target?.recordingHint &&
      navigation &&
      activeRef.current
    ) {
      navigation.navigate(
        {
          managementFlow: target.managementFlow,
          page: 'recordings',
          flow,
          id: image.request.id,
          auditlogHint: image.request.auditlog,
          ...(target.sessionId ? { sessionId: target.sessionId } : {}),
        },
        true,
      );
    }
  }
  async function open(request: ArtifactRequest, summary?: RecordingSummary) {
    if (remoteDisabled || disabled || operation.current !== null) {
      return;
    }
    if (request.kind !== (view === 'recordings' ? 'recording' : 'audit')) {
      return;
    }
    const chosenFile = managed ? keyInput.current?.files?.[0] : undefined;
    const chosenPassphrase = managed
      ? (form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ?? '')
      : '';
    resetResult();
    if (!managed) {
      clearInputs();
    }
    setReceived(null);
    setProtection(null);
    setOpened(request);
    setSelection(summary ?? null);
    setRecordingFlow(summary?.flow ?? '');
    setRecordingSession(summary?.sessionId ?? '');
    setFilePage(0);
    if (!managed) {
      setSensitive(false);
    }
    const expected = identity();
    await run('downloading', async (signal, token, stage) => {
      artifactFields(request);
      const report = (value: Progress) => {
        if (current(token, signal)) {
          setProgress(value);
        }
      };
      const image = await access.downloadArtifact(request, signal, report);
      if (!current(token, signal)) {
        return;
      }
      if (!matchesRoute(request)) {
        throw new EvidenceError('cancelled');
      }
      setReceived(image);
      // Opening a recording only downloads bytes. Header inspection itself is
      // an integrity check and must also wait for the explicit verify action.
      if (request.kind === 'recording' && !managed) {
        return;
      }
      stage('inspecting');
      const header = await inspectProtection(image, signal, scope, report);
      if (!current(token, signal)) {
        return;
      }
      setProtection(header);
      if (expected.source === 'reported') {
        setProducer(header.producer);
      }
      let key =
        level === 'outer' || header.expectedRecipient === ''
          ? null
          : secrets.matching(header.expectedRecipient);
      if (managed && chosenFile && level === 'private' && header.expectedRecipient !== '') {
        if (chosenFile.size < 1 || chosenFile.size > 64 << 10) {
          throw new EvidenceError('key');
        }
        const bytes = await readLocalBytes(chosenFile, signal);
        try {
          key = { file: new Blob([bytes]), passphrase: chosenPassphrase };
        } finally {
          new Uint8Array(bytes).fill(0);
        }
      }
      if (level === 'outer' || header.expectedRecipient === '' || key !== null) {
        stage('verifying');
        await check(
          image,
          header,
          key,
          expected,
          signal,
          token,
          managed ? effectiveSensitive : false,
        );
      }
      if (activeRef.current) {
        heading.current?.focus({ preventScroll: true });
      }
    });
  }
  async function recheck() {
    if (received === null) {
      return;
    }
    const image = received;
    const previousHeader = protection;
    const file = keyInput.current?.files?.[0];
    const passphrase =
      form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ?? '';
    const expected = identity();
    if (!(managed && auditView?.local)) {
      resetResult();
    }
    await run(previousHeader ? 'verifying' : 'inspecting', async (signal, token, stage) => {
      const header =
        previousHeader ??
        (await inspectProtection(image, signal, scope, (value) => {
          if (current(token, signal)) {
            setProgress(value);
          }
        }));
      if (!current(token, signal)) {
        return;
      }
      setProtection(header);
      if (expected.source === 'reported') {
        setProducer(header.producer);
      }
      let key =
        level === 'outer' || header.expectedRecipient === ''
          ? null
          : secrets.matching(header.expectedRecipient);
      if (level === 'private' && file !== undefined) {
        if (header.expectedRecipient === '' || file.size < 1 || file.size > 64 << 10) {
          throw new EvidenceError('key');
        }
        const bytes = await readLocalBytes(file, signal);
        try {
          key = { file: new Blob([bytes]), passphrase };
        } finally {
          new Uint8Array(bytes).fill(0);
        }
      }
      if (level === 'private' && header.expectedRecipient !== '' && key === null) {
        return;
      }
      stage('verifying');
      await check(image, header, key, expected, signal, token);
    });
  }
  function closeLocal() {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    setPhase(null);
    resetResult();
    clearInputs();
    setReceived(null);
    setProtection(null);
    setOpened(null);
    setSelection(null);
    setDetails(false);
  }
  function close() {
    if (navigation && route) {
      if (view === 'recordings') {
        const { id: _id, recordingHint: _recording, ...parent } = route;
        navigation.navigate(returnRoute.current ?? parent);
      } else {
        navigation.navigate({ managementFlow: route.managementFlow, page: 'auditlogs' });
      }
    } else {
      closeLocal();
    }
  }
  function navigateRecording(auditlog: string, id: string, flow?: string) {
    if (navigation && route) {
      navigation.navigate({
        managementFlow: route.managementFlow,
        page: 'recordings',
        ...(flow ? { flow, id } : { recordingHint: id }),
        auditlogHint: auditlog,
        ...(route.sessionId ? { sessionId: route.sessionId } : {}),
      });
    }
  }
  function select(request: ArtifactRequest, summary?: RecordingSummary) {
    routedSummary.current = summary ?? null;
    if (navigation && route) {
      returnRoute.current = route.id || route.recordingHint ? null : route;
      if (request.kind === 'audit') {
        navigation.navigate({
          managementFlow: route.managementFlow,
          page: 'auditlogs',
          auditlog: request.auditlog,
        });
      } else {
        navigateRecording(request.auditlog, request.id, summary?.flow);
      }
    } else {
      void open(request, summary);
    }
  }
  const openedKey = JSON.stringify(
    opened === null
      ? null
      : opened.kind === 'audit'
        ? ['audit', opened.auditlog]
        : ['recording', opened.auditlog, opened.id],
  );
  const readRoute = useEffectEvent(() => {
    if (!route || !active || disabled) {
      return;
    }
    if (managed) {
      return;
    }
    const requested = view === 'recordings' ? (route.id ?? route.recordingHint) : route.auditlog;
    if (!requested) {
      if (opened !== null) {
        closeLocal();
      }
      return;
    }
    if (view === 'recordings' && !route.auditlogHint) {
      if (opened !== null) {
        closeLocal();
      }
      setID(requested);
      return;
    }
    const request: ArtifactRequest =
      view === 'recordings'
        ? { kind: 'recording', auditlog: route.auditlogHint ?? '', id: requested }
        : { kind: 'audit', auditlog: requested };
    const key = JSON.stringify(
      request.kind === 'audit'
        ? ['audit', request.auditlog]
        : ['recording', request.auditlog, request.id],
    );
    if (opened !== null && openedKey !== key) {
      closeLocal();
      return;
    }
    if (phase !== null || operation.current !== null) {
      return;
    }
    if (
      view === 'recordings' &&
      route.recordingHint &&
      verified?.metadata.validation === 'private' &&
      relationFlow(recordingFlow) &&
      (!route.flow || route.flow === recordingFlow) &&
      navigation
    ) {
      navigation.navigate(
        {
          managementFlow: route.managementFlow,
          page: 'recordings',
          flow: recordingFlow,
          id: route.recordingHint,
          auditlogHint: route.auditlogHint ?? '',
          ...(route.sessionId ? { sessionId: route.sessionId } : {}),
        },
        true,
      );
      return;
    }
    const selectionKey = JSON.stringify([key, route.flow, route.sessionId]);
    if (consumedRoute.current === key && opened !== null) {
      if (consumedSelection.current !== selectionKey) {
        consumedSelection.current = selectionKey;
        if (
          view === 'recordings' &&
          received !== null &&
          !(
            verified?.metadata.validation === 'private' &&
            recordingFlow &&
            recordingFlow === route.flow &&
            (!route.sessionId || recordingSession === route.sessionId)
          )
        ) {
          resetResult();
        }
      }
      return;
    }
    if (remoteDisabled) {
      return;
    }
    consumedSelection.current = selectionKey;
    consumedRoute.current = key;
    const summary = routedSummary.current;
    void open(
      request,
      request.kind === 'recording' &&
        summary?.id === request.id &&
        summary.auditlog === request.auditlog
        ? summary
        : undefined,
    );
  });
  // biome-ignore lint/correctness/useExhaustiveDependencies: Phase and opened identity advance serialized route reconciliation, never an automatic retry of a consumed request.
  useEffect(() => {
    if (active && !disabled && routeKey !== 'null') {
      readRoute();
    }
  }, [routeKey, active, disabled, remoteDisabled, phase, openedKey]);
  function save(data: Blob, filename: string) {
    try {
      downloads.current.save(data, filename);
    } catch (error) {
      reportUiError('artifact-save', error);
      setNotice('artifactSaveFailed');
    }
  }
  const integrated = useAdminDetail(
    view,
    auditEvent
      ? typeof auditEvent.record.id === 'string'
        ? auditEvent.record.id
        : auditEvent.id
      : opened
        ? opened.kind === 'recording'
          ? opened.id
          : opened.auditlog
        : null,
    close,
    auditEvent && opened?.kind === 'audit'
      ? [opened.auditlog, ...(auditEvent.flow ? [auditEvent.flow] : [])]
      : opened?.kind === 'recording' && (recordingFlow || selection?.flow)
        ? [recordingFlow || selection?.flow || '']
        : [],
  );
  const title = t(view === 'recordings' ? 'workspaceRecordings' : 'workspaceAuditlogs');
  const locked = disabled || phase !== null;
  const encrypted = (protection?.expectedRecipient ?? '') !== '';
  const cached = encrypted && secrets.has(protection?.expectedRecipient ?? '');
  const pinReady =
    !validateIdentity || (/^[0-9a-f]{64}$/u.test(producer) && !/^0+$/u.test(producer));
  const ready =
    received !== null &&
    (protection === null || level === 'outer' || !encrypted || candidate || cached) &&
    pinReady;
  const metadata = verified?.metadata;
  const flowMismatch = !!(
    navigation &&
    verified?.metadata.validation === 'private' &&
    ((route?.flow && recordingFlow && route.flow !== recordingFlow) ||
      (route?.sessionId && route.sessionId !== recordingSession))
  );
  const success = verified !== null && !flowMismatch;
  const keyNeeded = level === 'private' && encrypted && !cached && !candidate;
  useImperativeHandle(controlRef, () => ({
    showDetails: () => setDetails(true),
    openOptions: () => {
      setVerificationInput(managed && (!received || !keyNeeded) ? 'fresh' : 'received');
      clearInputs();
      setOptionsOpen(true);
    },
    cancel: () => {
      operation.current?.abort();
      clearInputs();
    },
  }));
  const stateStatus = notice
    ? t(notice)
    : success
      ? t(
          metadata?.validation === 'outer'
            ? 'artifactOuterVerified'
            : used?.enabled && used.source === 'user'
              ? 'artifactVerificationOK'
              : 'artifactVerificationUnpinned',
        )
      : keyNeeded
        ? t('artifactKeyNeeded')
        : undefined;
  useEffect(() => {
    onEvidenceState?.({
      phase,
      progress,
      hasGrid: !!(
        verified?.output &&
        metadata?.kind === 'audit' &&
        metadata.outputFormat === 'jsonl'
      ),
      received: received !== null,
      status: stateStatus,
      result:
        notice && failedStage !== null && notice !== 'artifactCancelled'
          ? 'failure'
          : success
            ? 'success'
            : undefined,
    });
  }, [
    onEvidenceState,
    phase,
    progress,
    verified,
    metadata,
    received,
    stateStatus,
    notice,
    failedStage,
    success,
  ]);
  const appliedSensitive = useRef(effectiveSensitive);
  const applySensitive = useEffectEvent(() => {
    if (appliedSensitive.current !== effectiveSensitive) {
      appliedSensitive.current = effectiveSensitive;
      if (view === 'auditlogs' && received !== null && operation.current === null) {
        if (!managed || auditView?.local) {
          void recheck();
        } else {
          resetResult();
        }
      }
    }
  });
  // biome-ignore lint/correctness/useExhaustiveDependencies: Only an explicit, actor/source-owned eye change may reproject existing local bytes, never unrelated state or route activation.
  useEffect(() => {
    applySensitive();
  }, [effectiveSensitive]);
  const openByID = (
    <ArtifactOpenByID
      view={view}
      auditlog={auditlog}
      id={id}
      disabled={disabled || remoteDisabled}
      onAuditlog={setAuditlog}
      onID={setID}
      onGo={() => {
        if (navigation && route) {
          returnRoute.current = route.id || route.recordingHint ? null : route;
          if (view === 'recordings') {
            navigateRecording(auditlog, id);
          } else {
            navigation.navigate({
              managementFlow: route.managementFlow,
              page: 'auditlogs',
              auditlog,
              ...(id ? { eventHint: id } : {}),
            });
          }
        } else {
          void open(
            view === 'recordings'
              ? { kind: 'recording', auditlog, id }
              : { kind: 'audit', auditlog },
          );
        }
      }}
    />
  );
  const verificationControls = (
    <>
      {(success || notice || flowMismatch) && (
        <VerificationResultButton
          result={success && !notice ? 'success' : 'failure'}
          disabled={locked}
          onClick={() => setDetails(true)}
        />
      )}
      <Tooltip title={t(phase ? 'artifactCancel' : 'verifyOpen')}>
        <span>
          <IconButton
            color="inherit"
            aria-label={t(phase ? 'artifactCancel' : 'verifyOpen')}
            disabled={disabled || (!phase && received === null)}
            onClick={() => {
              if (phase) {
                operation.current?.abort();
                clearInputs();
              } else if (protection !== null && !keyNeeded) {
                void recheck();
              } else {
                clearInputs();
                setOptionsOpen(true);
              }
            }}
          >
            {phase ? <CancelIcon /> : <LicenseIcon />}
          </IconButton>
        </span>
      </Tooltip>
    </>
  );
  return (
    <section
      className="stack artifact-panel"
      aria-label={regionLabel ?? title}
      data-key-cache-revision={cacheRevision}
      data-evidence-phase={phase ?? 'idle'}
      data-evidence-input={received !== null}
    >
      {!integrated && !hideBreadcrumbs && (
        <AdminBreadcrumbs
          items={[
            { label: t('workspaceBifroest') },
            { label: title, ...(opened ? { onClick: close } : {}) },
            ...(opened?.kind === 'recording' && (recordingFlow || selection?.flow)
              ? [{ label: recordingFlow || selection?.flow || '' }]
              : []),
            ...(opened
              ? [{ label: opened.kind === 'recording' ? opened.id : opened.auditlog }]
              : []),
          ]}
        />
      )}
      {opened && !auditEvent && !managed && <div ref={heading} tabIndex={-1} />}
      <div hidden={opened !== null}>
        {view === 'recordings' ? (
          <ArtifactCatalog
            access={access}
            ownerActive={active}
            disabled={disabled || remoteDisabled}
            active={
              active &&
              opened === null &&
              !(route && (route.id || route.recordingHint) && route.auditlogHint)
            }
            openByID={openByID}
            onSelect={(request, summary) => {
              select(request, summary);
            }}
            onSource={(name) => {
              if (navigation && route && (route.id || route.recordingHint) && !route.auditlogHint) {
                navigation.navigate({ ...route, auditlogHint: name }, true);
              }
            }}
          />
        ) : (
          <AuditCatalog
            access={access}
            disabled={disabled || remoteDisabled}
            active={active && opened === null && !route?.auditlog}
            openByID={openByID}
            onSelect={(request) => {
              select(request);
            }}
          />
        )}
      </div>
      {opened !== null && (
        <>
          {flowMismatch && <Alert color="red">{t('artifactFlowMismatch')}</Alert>}
          {!managed &&
            view === 'recordings' &&
            !(success && verified?.output && metadata?.outputFormat === 'cast') && (
              <section
                className={`recording-video${palette === 'dark' ? ' recording-video--dark' : ''}`}
                aria-label={t('playbackVideo')}
                aria-busy={phase !== null}
              >
                <div className="recording-overlay">
                  {phase ? (
                    <div className="stack recording-loading">
                      <span>
                        {t(
                          phase === 'downloading'
                            ? 'recordingOpening'
                            : phase === 'inspecting'
                              ? 'artifactInspecting'
                              : 'recordingVerifying',
                        )}
                      </span>
                      <ReadProgress value={progress} />
                    </div>
                  ) : (
                    <span>{t('playbackVerificationRequired')}</span>
                  )}
                </div>
                <div className="recording-controls">
                  <div className="recording-control-row">{verificationControls}</div>
                </div>
              </section>
            )}
          {received && (
            <>
              {!flowMismatch &&
                verified?.output &&
                metadata?.kind === 'recording' &&
                metadata.outputFormat === 'cast' && (
                  <RecordingPlayer
                    source={verified.output}
                    expected={{
                      id: verified.request.kind === 'recording' ? verified.request.id : '',
                      producer: used?.enabled && used.source === 'user' ? used.producer : '',
                      allowUntrusted: !(used?.enabled && used.source === 'user'),
                    }}
                    disabled={disabled}
                    active={active && (!managed || auditView?.local === true)}
                    autoPrepare
                    verificationControls={verificationControls}
                  />
                )}
              {verified?.output &&
                metadata?.kind === 'audit' &&
                metadata.outputFormat === 'jsonl' && (
                  <AuditEvents
                    source={verified.output}
                    initialIndex={auditIndex ?? undefined}
                    privateFieldsKnown={verifiedSensitive && effectiveSensitive}
                    active={active && (!managed || auditView?.local === true)}
                    selected={auditEvent}
                    onSelect={setAuditEvent}
                  />
                )}
            </>
          )}
        </>
      )}
      {received && opened?.kind === 'recording' && (
        <section className="recording-evidence">
          <ArtifactSourceDetails
            received={received}
            summary={selection}
            disabled={locked}
            page={filePage}
            onPage={setFilePage}
            onSave={save}
            showFiles={false}
            scope={access.snapshot().scope}
            relation={{ flow: recordingFlow, sessionId: recordingSession }}
          />
        </section>
      )}
      <VerificationDialog
        open={active && optionsOpen}
        source={opened?.auditlog ?? route?.auditlog ?? ''}
        kind={view === 'auditlogs' ? 'audit' : 'recording'}
        disabled={
          locked ||
          !pinReady ||
          (received === null ? remoteDisabled || !managed || !route?.auditlog : !ready)
        }
        onClose={() => {
          setOptionsOpen(false);
          clearInputs();
        }}
        onStart={() => {
          setOptionsOpen(false);
          if (managed && verificationInput === 'fresh' && route?.auditlog) {
            void open({ kind: 'audit', auditlog: route.auditlog });
          } else if (received) {
            void recheck();
          } else if (route?.auditlog) {
            void open({ kind: 'audit', auditlog: route.auditlog });
          }
        }}
        actions={
          <>
            {secrets.fingerprint() !== null && (
              <Button
                disabled={locked}
                onClick={() => {
                  secrets.clear();
                  setCacheRevision((value) => value + 1);
                }}
              >
                {t('artifactForgetKey')}
              </Button>
            )}
            {!flowMismatch && verified?.output && (
              <Button
                variant="default"
                disabled={locked}
                onClick={() => {
                  if (verified.output) {
                    save(
                      verified.output,
                      verified.request.kind === 'recording'
                        ? `recording-${verified.request.id}.cast`
                        : `audit-${verified.request.auditlog}.jsonl`,
                    );
                  }
                }}
              >
                {t('artifactSaveExport')}
              </Button>
            )}
          </>
        }
      >
        {managed && received && (
          <Select
            label={t('verificationInput')}
            value={verificationInput}
            disabled={locked}
            data={[
              { value: 'fresh', label: t('verificationFresh') },
              { value: 'received', label: t('verificationReceived') },
            ]}
            onChange={(value) => setVerificationInput(value === 'received' ? 'received' : 'fresh')}
          />
        )}
        {notice && (
          <Alert color="red" role="status">
            {t(notice)}
          </Alert>
        )}
        <Select
          label={t('artifactLevel')}
          value={level}
          disabled={locked}
          data={[
            { value: 'private', label: t('artifactPrivate') },
            { value: 'outer', label: t('artifactOuter') },
          ]}
          onChange={(value) => {
            setLevel(value === 'outer' ? 'outer' : 'private');
            resetResult();
            clearInputs();
          }}
        />
        {view === 'auditlogs' && (
          <Select
            label={t('artifactAuditScope')}
            value={scope}
            disabled={locked}
            data={[
              { value: 'complete', label: t('artifactComplete') },
              { value: 'captured-prefix', label: t('artifactPrefix') },
            ]}
            onChange={(value) => {
              setScope(value === 'captured-prefix' ? 'captured-prefix' : 'complete');
              setProtection(null);
              resetResult();
            }}
          />
        )}
        <Checkbox
          label={t('artifactCheckSigner')}
          checked={validateIdentity}
          disabled={locked}
          onChange={(event) => {
            setValidateIdentity(event.currentTarget.checked);
            resetResult();
          }}
        />
        <TextInput
          label={t('artifactExpectedProducer')}
          value={producer}
          disabled={locked || !validateIdentity}
          maxLength={64}
          onChange={(event) => {
            setProducer(event.currentTarget.value);
            setProducerSource('user');
            resetResult();
          }}
        />
        {producerSource === 'reported' && (
          <p className="caption subtle">{t('artifactSuggestedSigner')}</p>
        )}
        {(managed || (optionsOpen && (protection === null || encrypted))) &&
          level === 'private' && (
            <form
              ref={form}
              method="dialog"
              className="stack artifact-key"
              onSubmit={(event) => event.preventDefault()}
            >
              <p>{t(cached && !candidate ? 'artifactUsingCachedKey' : 'artifactKeyLocal')}</p>
              <label htmlFor={inputID}>{t('artifactKeyFile')}</label>
              <input
                key={keyRevision}
                ref={keyInput}
                id={inputID}
                name="evidence-private"
                type="file"
                disabled={locked}
                onChange={(event) => {
                  setCandidate((event.currentTarget.files?.length ?? 0) > 0);
                  const password = form.current?.querySelector<HTMLInputElement>(
                    '[name="evidence-passphrase"]',
                  );
                  if (password) {
                    password.value = '';
                  }
                }}
              />
              {candidate && (
                <PasswordInput
                  id={passwordID}
                  name="evidence-passphrase"
                  label={t('artifactPassphrase')}
                  autoComplete="off"
                  disabled={locked}
                />
              )}
            </form>
          )}
        {encrypted && verified !== null && (
          <Button
            disabled={locked}
            onClick={() => {
              resetResult();
              setCandidate(false);
            }}
          >
            {t('artifactReplaceKey')}
          </Button>
        )}
      </VerificationDialog>
      <Modal
        opened={active && details}
        onClose={() => setDetails(false)}
        title={t('recordingVerificationDetails')}
      >
        <div className="stack">
          {notice && <Alert color="red">{t(notice)}</Alert>}
          {received && (
            <Button
              variant="default"
              disabled={locked}
              onClick={() => {
                setDetails(false);
                clearInputs();
                setOptionsOpen(true);
              }}
            >
              {t('recordingChangeVerification')}
            </Button>
          )}
          {notice && received === null && opened && (
            <Button
              disabled={locked || remoteDisabled}
              onClick={() => {
                setDetails(false);
                void open(opened, selection ?? undefined);
              }}
            >
              {t('recordingRetryOpen')}
            </Button>
          )}
          <dl className="metadata-grid">
            <dt>{t('artifactDiagnosticCode')}</dt>
            <dd>{errorCode || '—'}</dd>
            <dt>{t('artifactDiagnosticStage')}</dt>
            <dd>{failedStage ?? phase ?? 'complete'}</dd>
            <dt>{t('artifactValidation')}</dt>
            <dd>{metadata?.validation ?? protection?.validation ?? '—'}</dd>
            <dt>{t('artifactVerifiedProducer')}</dt>
            <dd>{metadata?.producer ?? protection?.producer ?? '—'}</dd>
            <dt>{t('artifactExpectedProducer')}</dt>
            <dd>{used?.enabled ? used.producer : t('artifactSignerNotPinned')}</dd>
            <dt>{t('artifactTrust')}</dt>
            <dd>
              {t(
                used?.enabled && used.source === 'user'
                  ? 'artifactUserSelectedSigner'
                  : 'artifactSuggestedSigner',
              )}
            </dd>
            <dt>{t('artifactDerivedRecipient')}</dt>
            <dd>
              {metadata?.expectedRecipient ||
                protection?.expectedRecipient ||
                t('artifactNotEncrypted')}
            </dd>
            <dt>{t('artifactDecryption')}</dt>
            <dd>{metadata?.decryption ?? 'not-checked'}</dd>
            {metadata?.kind === 'audit' && (
              <>
                <dt>{t('artifactRecordCount')}</dt>
                <dd>{metadata.records}</dd>
                <dt>{t('artifactPrivateCount')}</dt>
                <dd>{metadata.privateRecords}</dd>
                <dt>{t('artifactAuditScope')}</dt>
                <dd>{metadata.auditScope}</dd>
              </>
            )}
          </dl>
          {received && (
            <>
              <ArtifactSourceDetails
                received={received}
                summary={selection}
                disabled={locked}
                page={filePage}
                onPage={setFilePage}
                onSave={save}
                showFiles={false}
              />
              <details>
                <summary>{t('artifactOriginalsAdvanced')}</summary>
                <ArtifactSourceDetails
                  received={received}
                  disabled={locked}
                  page={filePage}
                  onPage={setFilePage}
                  onSave={save}
                  showMetadata={false}
                />
              </details>
            </>
          )}
        </div>
      </Modal>
    </section>
  );
}
