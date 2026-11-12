import CancelIcon from '@mui/icons-material/Cancel';
import { IconButton, Tooltip } from '@mui/material';
import {
    useCallback,
    useContext,
    useEffect,
    useEffectEvent,
    useId,
    useImperativeHandle,
    useReducer,
    useRef,
    useState,
    useSyncExternalStore,
} from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { RecordingSummary } from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import type { OperationLease } from '../shared/operation';
import { uuidEqual, uuidText } from '../shared/uuid';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { useAdminDetail } from '../ui/admin-navigation';
import { reportUiError } from '../ui/error-report';
import { VerificationResultButton } from '../ui/GridWork';
import { bookmarkPath } from '../ui/hash-route';
import { LicenseIcon } from '../ui/LicenseIcon';
import { relationFlow } from '../ui/ManagementJump';
import { ManagementNotFound } from '../ui/ManagementNotFound';
import type { ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button, Modal, Select, useComputedColorScheme } from '../ui/material';
import { type Message, t } from '../ui/messages';
import { profileResetEvent } from '../ui/profile-reset';
import { ReadProgress } from '../ui/ReadProgress';
import { ArtifactCatalog } from './ArtifactCatalog';
import { ArtifactOpenByID } from './ArtifactOpenByID';
import { ArtifactSourceDetails } from './ArtifactSourceDetails';
import { AuditCatalog } from './AuditCatalog';
import { AuditEvents } from './AuditEvents';
import { AuditSourceContext } from './AuditSourceContext';
import { useAuditView } from './AuditViewContext';
import type { AuditEventRow } from './audit-events';
import { EvidenceDetailsDialog } from './EvidenceDetailsDialog';
import type { EvidenceFailure, SigningExpectation as UsedExpectation } from './evidence-details';
import { EvidenceJob } from './evidence-job';
import { EvidenceError, type EvidenceMetadata } from './evidence-protocol';
import { emptyEvidenceResult, evidenceResultTransition } from './evidence-result';
import type { ArtifactEvidencePanelProps, ArtifactPhase as Phase } from './evidence-view';
import { LocalArtifactDownload } from './local-download';
import { readEvidenceKey } from './local-key-input';
import type { RecordingInfo } from './open-recording';
import { PreparedPlayback } from './prepared-playback';
import { inspectProtection } from './protection';
import { type ArtifactRequest, artifactFields, type ReceivedArtifact } from './protocol';
import { RecordingPlayer } from './RecordingPlayer';
import { type LocalRecordingIndex, recordingVerificationFromIndex } from './recording-index';
import { prepareRecordingPreview } from './recording-preview';
import { RecordingRuntimeOwner } from './recording-runtime-owner';
import { useArtifactSecrets } from './session-secrets';
import { validSigningID } from './signing-id';
import { VerificationDialog } from './VerificationDialog';
import { LocalKeyFields, VerificationFields } from './VerificationFields';
import type { EvidenceKey, RecordingRuntime } from './verify';
import { verifyEvidence } from './verify-evidence';
import './recording-player.css';

function failure(error: unknown): Message {
    if (error instanceof EvidenceError) {
        return error.code === 'key-required'
            ? 'artifactKeyNeeded'
            : error.code === 'key'
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
    mode = 'standalone',
    onEvidenceState,
    onResultReady,
}: ArtifactEvidencePanelProps) {
    const palette = useComputedColorScheme('light');
    const auditView = useAuditView();
    const sourceHints = useContext(AuditSourceContext);
    const managed = mode === 'audit-verification';
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
    const [receipt, updateReceipt] = useReducer(
        evidenceResultTransition,
        undefined,
        emptyEvidenceResult,
    );
    const { recordingFlow, recordingSession, verified, auditIndex, verifiedSensitive, used } =
        receipt;
    const [auditEvent, setAuditEvent] = useState<AuditEventRow | null>(null);
    const inputID = useId();
    const passwordID = useId();
    const decryptInputID = useId();
    const decryptPasswordID = useId();
    const [opened, setOpened] = useState<ArtifactRequest | null>(null);
    const [selection, setSelection] = useState<RecordingSummary | null>(null);
    const [received, setReceived] = useState<ReceivedArtifact | null>(null);
    const [protection, setProtection] = useState<EvidenceMetadata | null>(null);
    const sourceVerification = useRef<{
        access: WebAccess;
        index: LocalRecordingIndex | null;
    }>({ access, index: null });
    const captureVerificationIndex = useCallback(
        (index: LocalRecordingIndex | null) => {
            sourceVerification.current = { access, index };
        },
        [access],
    );
    useEffect(() => {
        const clear = () => {
            sourceVerification.current = { access, index: null };
        };
        window.addEventListener(profileResetEvent, clear);
        return () => window.removeEventListener(profileResetEvent, clear);
    }, [access]);
    const attemptedVerification = useRef(false);
    const [playback, setPlayback] = useState<{ source: Blob; image: PreparedPlayback } | null>(
        null,
    );
    const [recordingInfo, setRecordingInfo] = useState<RecordingInfo | null>(null);
    const [decryptOpen, setDecryptOpen] = useState(false);
    useEffect(
        () => () => {
            playback?.image.dispose();
        },
        [playback],
    );
    const [job] = useState(() => new EvidenceJob());
    const { phase, progress } = useSyncExternalStore(job.subscribe, job.getSnapshot);
    const setProgress = job.progress;
    useEffect(() => {
        onPhaseChange?.(phase);
    }, [onPhaseChange, phase]);
    const [notice, setNotice] = useState<Message | null>(null);
    const [errorCode, setErrorCode] = useState('');
    const [failedStage, setFailedStage] = useState<Phase | null>(null);
    const [verificationFailure, setVerificationFailure] = useState<EvidenceFailure | null>(null);
    const [operationDetails, setOperationDetails] = useState(false);
    const [details, setDetails] = useState(false);
    const [filePage, setFilePage] = useState(0);
    const [candidate, setCandidate] = useState(false);
    const [keyRevision, setKeyRevision] = useState(0);
    const [cacheRevision, setCacheRevision] = useState(0);
    const [validateIdentity, setValidateIdentity] = useState(false);
    const [producer, setProducer] = useState('');
    const [producerSource, setProducerSource] = useState<'reported' | 'user'>('reported');
    const seeded = useRef('');
    const expectedSource = useRef('');
    const seedSigner = useEffectEvent((value: string, sourceChanged = false) => {
        if (
            validSigningID(value) &&
            (sourceChanged || producerSource === 'reported') &&
            seeded.current === ''
        ) {
            seeded.current = value;
            setProducer(value);
            setProducerSource('reported');
            setValidateIdentity(true);
        }
    });
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
    // Sibling dialogs overlap during exit transitions. Unmounting the old
    // decrypt input must not clear the active verification dialog's refs.
    const decryptKeyInput = useRef<HTMLInputElement | null>(null);
    const decryptForm = useRef<HTMLFormElement | null>(null);
    const recordingRuntime = useRef<{
        access: WebAccess;
        value: RecordingRuntimeOwner;
    } | null>(null);
    function retireRecordingRuntime() {
        const current = recordingRuntime.current;
        recordingRuntime.current = null;
        current?.value.dispose();
    }
    async function runtimeFor(
        image: ReceivedArtifact,
        signal: AbortSignal,
    ): Promise<RecordingRuntime> {
        let owner = recordingRuntime.current;
        if (!owner || owner.access !== access) {
            retireRecordingRuntime();
            owner = { access, value: new RecordingRuntimeOwner(() => ownerRef.current === access) };
            recordingRuntime.current = owner;
        }
        return owner.value.acquire(image, signal);
    }
    const downloads = useRef(new LocalArtifactDownload());
    const forgetEvidence = useEffectEvent(() => {
        retireRecordingRuntime();
        setOptionsOpen(false);
        job.retire();
        downloads.current.clear();
        clearInputs();
        setOpened(null);
        setSelection(null);
        setReceived(null);
        attemptedVerification.current = false;
        setPlayback(null);
        setRecordingInfo(null);
        setDecryptOpen(false);
        seeded.current = '';
        expectedSource.current = '';
        setProtection(null);
        updateReceipt({ type: 'clear' });
        setVerificationFailure(null);
        setNotice(null);
        setDetails(false);
        setAuditEvent(null);
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
        for (const [file, owner] of [
            [keyInput, form],
            [decryptKeyInput, decryptForm],
        ] as const) {
            if (file.current) {
                file.current.value = '';
            }
            const input = owner.current?.querySelector<HTMLInputElement>(
                '[name="evidence-passphrase"]',
            );
            if (input) {
                input.value = '';
            }
        }
        setCandidate(false);
        setKeyRevision((value) => value + 1);
    };
    const cancelFromOutside = useEffectEvent(() => {
        job.cancel();
        clearInputs();
        if (job.busy) {
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
        retireRecordingRuntime();
        job.retire();
        downloads.current.clear();
        setOpened(null);
        setSelection(null);
        consumedRoute.current = null;
        consumedSelection.current = null;
        returnRoute.current = null;
        routedSummary.current = null;
        setAuditEvent(null);
        setReceived(null);
        attemptedVerification.current = false;
        setPlayback(null);
        setRecordingInfo(null);
        setDecryptOpen(false);
        seeded.current = '';
        expectedSource.current = '';
        setProtection(null);
        updateReceipt({ type: 'clear' });
        setVerificationFailure(null);
        setNotice(null);
        setDetails(false);
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
            retireRecordingRuntime();
            job.retire();
            downloads.current.clear();
        };
    }, [access, disabled, view]);
    useEffect(() => {
        if (
            !disabled &&
            view === 'auditlogs' &&
            ownerRef.current === access &&
            producerSource === 'reported' &&
            auditView?.producerId
        ) {
            seedSigner(auditView.producerId);
        }
    }, [access, disabled, view, producerSource, auditView?.producerId]);
    // biome-ignore lint/correctness/useExhaustiveDependencies: Hide portals and clear unvalidated inputs on deactivation; retain the explicitly approved tab key cache.
    useEffect(() => {
        if (!active) {
            retireRecordingRuntime();
            setOptionsOpen(false);
            setDecryptOpen(false);
            if (!backgroundAllowed) {
                job.cancel();
            }
            clearInputs();
            setDetails(false);
        }
    }, [active, backgroundAllowed]);
    const current = (token: OperationLease, signal: AbortSignal) =>
        token.current() &&
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
            uuidEqual(target.id ?? target.recordingHint, request.id) &&
            target.auditlogHint === request.auditlog
        );
    }
    async function run(
        next: Phase,
        action: (
            signal: AbortSignal,
            token: OperationLease,
            stage: (phase: Phase) => void,
        ) => Promise<void>,
    ) {
        if (disabled || (!active && !backgroundAllowed) || job.busy) {
            return;
        }
        setNotice(null);
        setErrorCode('');
        setFailedStage(null);
        if (managed || next === 'verifying' || next === 'inspecting') {
            setVerificationFailure(null);
        }
        await job.run(
            next,
            (token, stage) => action(token.signal, token, stage),
            (error, stage) => {
                if (ownerRef.current === access) {
                    reportUiError('artifact', error);
                    setNotice(failure(error));
                    setFailedStage(stage);
                    if (managed || stage === 'verifying' || stage === 'inspecting') {
                        setVerificationFailure({
                            message: failure(error),
                            code:
                                error instanceof EvidenceError || error instanceof RememberMeError
                                    ? error.code
                                    : 'unavailable',
                            stage,
                        });
                    }
                    setErrorCode(
                        error instanceof EvidenceError || error instanceof RememberMeError
                            ? error.code
                            : 'unavailable',
                    );
                }
            },
            () => {
                if (ownerRef.current === access) {
                    clearInputs();
                }
            },
        );
    }
    function resetResult() {
        setVerificationFailure(null);
        updateReceipt({ type: 'invalidate-verification' });
        setAuditEvent(null);
        downloads.current.clear();
        setNotice(null);
    }
    async function check(
        image: ReceivedArtifact,
        header: Pick<EvidenceMetadata, 'producer' | 'expectedRecipient'>,
        key: EvidenceKey | null,
        expectation: UsedExpectation,
        signal: AbortSignal,
        token: OperationLease,
        includeSensitive = effectiveSensitive,
    ) {
        const checked = {
            ...expectation,
            producer: expectation.enabled ? expectation.producer : '',
        };
        if (current(token, signal) && !(managed && auditView?.local)) {
            updateReceipt({ type: 'expectation', value: checked });
        }
        const completed = await verifyEvidence(
            image,
            header,
            key,
            {
                expectation,
                level,
                auditScope: scope,
                sensitive: includeSensitive,
                indexAudit: managed,
            },
            {
                signal,
                current: () => current(token, signal),
                matches: () => matchesRoute(image.request),
                target: () => routeRef.current,
                recording: runtimeFor,
                progress: setProgress,
            },
        );
        if (!current(token, signal)) {
            return;
        }
        const { verified: result, auditIndex: preparedIndex, context } = completed;
        const flow = context.flow;
        const target = routeRef.current;
        if (key !== null) {
            secrets.remember(key, result);
            setCacheRevision((value) => value + 1);
        }
        resetResult();
        updateReceipt({
            type: 'verified',
            value: result,
            index: preparedIndex,
            sensitive: includeSensitive,
            expectation: checked,
            flow,
            session: context.sessionId,
        });
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
                    ...(target.flow ? { flow: target.flow } : {}),
                    id: image.request.id,
                    auditlogHint: image.request.auditlog,
                    ...(target.sessionId ? { sessionId: target.sessionId } : {}),
                },
                true,
            );
        }
    }
    async function open(request: ArtifactRequest, summary?: RecordingSummary) {
        if (remoteDisabled || disabled || job.busy) {
            return;
        }
        if (request.kind !== (view === 'recordings' ? 'recording' : 'audit')) {
            return;
        }
        const sourceChanged =
            request.kind === 'recording' && expectedSource.current !== request.auditlog;
        if (sourceChanged) {
            expectedSource.current = request.auditlog;
            seeded.current = '';
            setProducer('');
            setProducerSource('reported');
            setValidateIdentity(false);
        }
        const chosenFile = managed ? keyInput.current?.files?.[0] : undefined;
        const chosenPassphrase = managed
            ? (form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')
                  ?.value ?? '')
            : '';
        resetResult();
        retireRecordingRuntime();
        attemptedVerification.current = false;
        if (!managed) {
            clearInputs();
        }
        setReceived(null);
        setPlayback(null);
        setRecordingInfo(null);
        setDecryptOpen(false);
        setProtection(null);
        setOpened(request);
        setSelection(summary ?? null);
        updateReceipt({
            type: 'relation',
            flow: summary?.flow ?? '',
            session: summary?.sessionId ?? '',
        });
        setFilePage(0);
        if (!managed) {
            setSensitive(false);
        }
        const expected = identity();
        if (managed || request.kind === 'audit') {
            updateReceipt({ type: 'expectation', value: expected });
        }
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
            seedSigner(
                'ProducerID' in image.metadata
                    ? image.metadata.ProducerID.toLowerCase()
                    : image.metadata.Producer.toLowerCase(),
                sourceChanged,
            );
            if (request.kind === 'recording' && !managed) {
                stage('preparing');
                await prepareRecording(image, null, signal, token);
                const binding = sourceVerification.current;
                const cached = await recordingVerificationFromIndex(
                    binding.access === access ? binding.index : null,
                    image,
                    signal,
                );
                if (
                    cached &&
                    sourceVerification.current === binding &&
                    current(token, signal) &&
                    matchesRoute(request)
                ) {
                    setLevel('private');
                    updateReceipt({
                        type: 'verified',
                        value: cached.verified,
                        index: null,
                        sensitive: false,
                        expectation: {
                            enabled: cached.verified.metadata.trust === 'pinned',
                            producer:
                                cached.verified.metadata.trust === 'pinned'
                                    ? cached.verified.metadata.producer
                                    : '',
                            source: cached.reported ? 'reported' : 'user',
                        },
                        flow: cached.verified.metadata.recordingContext?.flow ?? '',
                        session: cached.verified.metadata.recordingContext?.sessionId ?? '',
                    });
                }
                return;
            }
            stage('inspecting');
            const header = await inspectProtection(image, signal, scope, report);
            if (!current(token, signal)) {
                return;
            }
            setProtection(header);
            let key =
                level === 'outer' || header.expectedRecipient === ''
                    ? null
                    : secrets.matching(header.expectedRecipient);
            if (managed && chosenFile && level === 'private' && header.expectedRecipient !== '') {
                key = await readEvidenceKey(chosenFile, chosenPassphrase, signal);
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
            } else {
                throw new EvidenceError('key-required');
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
        attemptedVerification.current = true;
        const previousHeader = protection;
        const file = keyInput.current?.files?.[0];
        const passphrase =
            form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ??
            '';
        const expected = identity();
        if (!(managed && auditView?.local)) {
            resetResult();
        }
        updateReceipt({ type: 'expectation', value: expected });
        const hadPlayback = playback !== null;
        if (image.request.kind === 'recording') {
            setPlayback(null);
        }
        await run(
            previousHeader || recordingInfo ? 'verifying' : 'inspecting',
            async (signal, token, stage) => {
                const header =
                    image.request.kind === 'recording' && recordingInfo
                        ? {
                              producer: recordingInfo.producer,
                              expectedRecipient: recordingInfo.recipient,
                          }
                        : (previousHeader ??
                          (await inspectProtection(image, signal, scope, (value) => {
                              if (current(token, signal)) {
                                  setProgress(value);
                              }
                          })));
                if (!current(token, signal)) {
                    return;
                }
                if ('validation' in header) {
                    setProtection(header as EvidenceMetadata);
                }
                let key =
                    level === 'outer' || header.expectedRecipient === ''
                        ? null
                        : secrets.matching(header.expectedRecipient);
                if (level === 'private' && file !== undefined) {
                    if (header.expectedRecipient === '') {
                        throw new EvidenceError('key');
                    }
                    key = await readEvidenceKey(file, passphrase, signal);
                }
                if (level === 'private' && header.expectedRecipient !== '' && key === null) {
                    throw new EvidenceError('key-required');
                }
                stage('verifying');
                await check(image, header, key, expected, signal, token);
                if (
                    image.request.kind === 'recording' &&
                    (level === 'private' || hadPlayback) &&
                    current(token, signal)
                ) {
                    stage('preparing');
                    await prepareRecording(image, key, signal, token);
                }
            },
        );
    }
    async function prepareRecording(
        image: ReceivedArtifact,
        key: EvidenceKey | null,
        signal: AbortSignal,
        token: OperationLease,
    ) {
        setProgress(null);
        const runtime = await runtimeFor(image, signal);
        const result = await prepareRecordingPreview(runtime, image, key, {
            signal,
            current: () => current(token, signal),
            target: () => routeRef.current,
            keys: secrets,
            information: setRecordingInfo,
            keyRemembered: () => setCacheRevision((value) => value + 1),
        });
        // The controller's result crosses an await boundary. A route/access reset
        // in that interval still must not publish the decoded image to a new owner.
        if (!current(token, signal)) {
            if (result?.kind === 'ready') {
                result.image.dispose();
            }
            return;
        }
        if (result?.kind === 'key-required') {
            setDecryptOpen(true);
        } else if (result?.kind === 'ready') {
            setDecryptOpen(false);
            setPlayback({ source: result.source, image: new PreparedPlayback(result.image) });
        }
    }
    async function decodeRecording() {
        if (!received) {
            return;
        }
        const image = received;
        const file = decryptKeyInput.current?.files?.[0];
        const passphrase =
            decryptForm.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')
                ?.value ?? '';
        await run('preparing', async (signal, token) => {
            let key = recordingInfo?.encrypted ? secrets.matching(recordingInfo.recipient) : null;
            if (file) {
                key = await readEvidenceKey(file, passphrase, signal);
            }
            setPlayback(null);
            await prepareRecording(image, key, signal, token);
        });
    }
    function closeLocal() {
        retireRecordingRuntime();
        job.retire();
        resetResult();
        clearInputs();
        setReceived(null);
        setPlayback(null);
        setRecordingInfo(null);
        setDecryptOpen(false);
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
    function navigateRecording(auditlog: string, id: string) {
        if (navigation && route) {
            navigation.navigate({
                managementFlow: route.managementFlow,
                page: 'recordings',
                id,
                ...(route.flow ? { flow: route.flow } : {}),
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
                navigateRecording(request.auditlog, request.id);
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
        const requested =
            view === 'recordings' ? (route.id ?? route.recordingHint) : route.auditlog;
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
        if (phase !== null || job.busy) {
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
                    ...(route.flow ? { flow: route.flow } : {}),
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
                    recordingInfo &&
                    ((route.flow && route.flow !== recordingInfo.flow) ||
                        (route.sessionId && !uuidEqual(route.sessionId, recordingInfo.sessionId)))
                ) {
                    setPlayback(null);
                }
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
                summary &&
                uuidEqual(summary.id, request.id) &&
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
    const recipient = recordingInfo?.recipient ?? protection?.expectedRecipient ?? '';
    const encrypted = recordingInfo?.encrypted ?? recipient !== '';
    const cached = encrypted && secrets.has(recipient);
    const pinReady =
        !validateIdentity || (/^[0-9a-f]{64}$/u.test(producer) && !/^0+$/u.test(producer));
    const ready =
        received !== null &&
        ((protection === null && recordingInfo === null) ||
            level === 'outer' ||
            !encrypted ||
            candidate ||
            cached) &&
        pinReady;
    const metadata = verified?.metadata;
    const flowMismatch = !!(
        navigation &&
        verified?.metadata.validation === 'private' &&
        ((route?.flow && recordingFlow && route.flow !== recordingFlow) ||
            (route?.sessionId && !uuidEqual(route.sessionId, recordingSession)))
    );
    const success = verified !== null && !flowMismatch;
    const keyNeeded = level === 'private' && encrypted && !cached && !candidate;
    useImperativeHandle(controlRef, () => ({
        showDetails: () => {
            setOperationDetails(false);
            setDetails(true);
        },
        openOptions: (privateFields = false) => {
            if (privateFields) {
                setLevel('private');
            }
            const needsKey = privateFields ? encrypted && !cached : keyNeeded;
            setVerificationInput(managed && (!received || !needsKey) ? 'fresh' : 'received');
            clearInputs();
            setOptionsOpen(true);
        },
        cancel: () => {
            job.cancel();
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
                verificationFailure && verificationFailure.message !== 'artifactCancelled'
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
        verificationFailure,
        success,
    ]);
    const appliedSensitive = useRef(effectiveSensitive);
    const applySensitive = useEffectEvent(() => {
        if (appliedSensitive.current !== effectiveSensitive) {
            appliedSensitive.current = effectiveSensitive;
            if (view === 'auditlogs' && received !== null && !job.busy) {
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
            auditlog={view === 'recordings' ? (route?.auditlogHint ?? auditlog) : auditlog}
            fixedSource={view === 'recordings' && !!route?.auditlogHint}
            id={id}
            disabled={disabled || remoteDisabled}
            onAuditlog={setAuditlog}
            onID={setID}
            onGo={() => {
                if (navigation && route) {
                    returnRoute.current = route.id || route.recordingHint ? null : route;
                    if (view === 'recordings') {
                        navigateRecording(route.auditlogHint ?? auditlog, id);
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
            {(success || verificationFailure || flowMismatch) && (
                <VerificationResultButton
                    result={success && !verificationFailure ? 'success' : 'failure'}
                    disabled={locked}
                    onClick={() => {
                        setOperationDetails(false);
                        setDetails(true);
                    }}
                />
            )}
            {(!success ||
                attemptedVerification.current ||
                verificationFailure ||
                flowMismatch ||
                phase) && (
                <Tooltip title={t(phase ? 'artifactCancel' : 'verifyOpen')}>
                    <span>
                        <IconButton
                            color="inherit"
                            aria-label={t(phase ? 'artifactCancel' : 'verifyOpen')}
                            disabled={disabled || (!phase && received === null)}
                            onClick={() => {
                                if (phase) {
                                    job.cancel();
                                    clearInputs();
                                } else if (
                                    (protection !== null || recordingInfo !== null) &&
                                    attemptedVerification.current &&
                                    !keyNeeded
                                ) {
                                    void recheck();
                                } else {
                                    clearInputs();
                                    setDecryptOpen(false);
                                    setOptionsOpen(true);
                                }
                            }}
                        >
                            {phase ? <CancelIcon /> : <LicenseIcon />}
                        </IconButton>
                    </span>
                </Tooltip>
            )}
        </>
    );
    const entityNotFound =
        !managed &&
        view === 'recordings' &&
        !!(route?.id ?? route?.recordingHint) &&
        errorCode === 'not-found' &&
        phase === null;
    return (
        <section
            className="stack artifact-panel"
            aria-label={regionLabel ?? title}
            data-key-cache-revision={cacheRevision}
            data-evidence-phase={phase ?? 'idle'}
            data-evidence-input={received !== null}
            data-management-entity-missing={entityNotFound || undefined}
        >
            {entityNotFound && <ManagementNotFound />}
            {!integrated && !hideBreadcrumbs && (
                <AdminBreadcrumbs
                    items={[
                        {
                            label: t('workspaceBifroest'),
                            to: bookmarkPath(access.snapshot().scope, {
                                managementFlow: access.snapshot().flow?.name ?? 'management',
                                page: 'server',
                            }),
                        },
                        {
                            label: title,
                            to: bookmarkPath(access.snapshot().scope, {
                                managementFlow: access.snapshot().flow?.name ?? 'management',
                                page: view,
                            }),
                            ...(opened ? { onClick: close } : {}),
                        },
                        ...(opened?.kind === 'recording' && (recordingFlow || selection?.flow)
                            ? [
                                  {
                                      label: recordingFlow || selection?.flow || '',
                                      to: bookmarkPath(access.snapshot().scope, {
                                          managementFlow:
                                              access.snapshot().flow?.name ?? 'management',
                                          page: view,
                                          auditlogHint: opened.auditlog,
                                          flow: recordingFlow || selection?.flow || '',
                                      }),
                                  },
                              ]
                            : []),
                        ...(opened
                            ? [
                                  {
                                      label:
                                          opened.kind === 'recording'
                                              ? uuidText(opened.id)
                                              : opened.auditlog,
                                      to: bookmarkPath(access.snapshot().scope, {
                                          managementFlow:
                                              access.snapshot().flow?.name ?? 'management',
                                          page: view,
                                          ...(opened.kind === 'recording'
                                              ? { auditlogHint: opened.auditlog, id: opened.id }
                                              : { auditlog: opened.auditlog }),
                                      }),
                                  },
                              ]
                            : []),
                    ]}
                />
            )}
            {opened && !auditEvent && !managed && <div ref={heading} tabIndex={-1} />}
            <div hidden={opened !== null}>
                {view === 'recordings' && route && !route.auditlogHint ? (
                    <AuditCatalog
                        access={access}
                        disabled={disabled || remoteDisabled}
                        active={active && opened === null}
                        openByID={openByID}
                        onSelect={(request) =>
                            navigation?.navigate({
                                managementFlow: route.managementFlow,
                                page: 'auditlogs',
                                auditlog: request.auditlog,
                                ...(route.flow ? { flow: route.flow } : {}),
                                ...(route.sessionId ? { sessionId: route.sessionId } : {}),
                            })
                        }
                        onRecordings={(source) => {
                            sourceHints?.select(source);
                            navigation?.navigate({ ...route, auditlogHint: source.name });
                        }}
                    />
                ) : view === 'recordings' ? (
                    <ArtifactCatalog
                        onVerificationIndex={captureVerificationIndex}
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
                            if (
                                navigation &&
                                route &&
                                (route.id || route.recordingHint) &&
                                !route.auditlogHint
                            ) {
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
                    {!managed && view === 'recordings' && (playback === null || phase !== null) && (
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
                                                    : phase === 'preparing'
                                                      ? 'playbackPreparing'
                                                      : phase === 'inspecting'
                                                        ? 'artifactInspecting'
                                                        : 'recordingVerifying',
                                            )}
                                        </span>
                                        <ReadProgress value={progress} />
                                    </div>
                                ) : (
                                    <div className="stack">
                                        {notice && <span>{t(notice)}</span>}
                                        <Button
                                            disabled={locked || !received}
                                            onClick={() => {
                                                void decodeRecording();
                                            }}
                                        >
                                            {t(
                                                recordingInfo?.requiresKey
                                                    ? 'artifactUnlock'
                                                    : 'recordingOpen',
                                            )}
                                        </Button>
                                        {notice && (
                                            <Button
                                                variant="subtle"
                                                onClick={() => {
                                                    setOperationDetails(true);
                                                    setDetails(true);
                                                }}
                                            >
                                                {t('detailsTitle')}
                                            </Button>
                                        )}
                                    </div>
                                )}
                            </div>
                            <div className="recording-verification">{verificationControls}</div>
                        </section>
                    )}
                    {received && (
                        <>
                            {playback &&
                                phase === null &&
                                view === 'recordings' &&
                                !(
                                    recordingInfo &&
                                    ((route?.flow && route.flow !== recordingInfo.flow) ||
                                        (route?.sessionId &&
                                            !uuidEqual(route.sessionId, recordingInfo.sessionId)))
                                ) && (
                                    <RecordingPlayer
                                        source={playback.source}
                                        preparedImage={playback.image}
                                        onPrepare={() => {
                                            void decodeRecording();
                                        }}
                                        expected={{
                                            id:
                                                received.request.kind === 'recording'
                                                    ? received.request.id
                                                    : '',
                                            producer: '',
                                            allowUntrusted: true,
                                            unchecked: true,
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
            <Modal
                opened={active && decryptOpen}
                onClose={() => {
                    setDecryptOpen(false);
                    clearInputs();
                }}
                title={t('recordingDecrypt')}
            >
                {notice && <Alert color="red">{t(notice)}</Alert>}
                <LocalKeyFields
                    input={decryptKeyInput}
                    form={decryptForm}
                    id={decryptInputID}
                    passwordID={decryptPasswordID}
                    revision={keyRevision}
                    candidate={candidate}
                    onCandidate={setCandidate}
                    disabled={locked}
                />
                <Button
                    disabled={locked || !candidate}
                    onClick={() => {
                        setDecryptOpen(false);
                        void decodeRecording();
                    }}
                >
                    {t('artifactUnlock')}
                </Button>
            </Modal>
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
                        onChange={(value) =>
                            setVerificationInput(value === 'received' ? 'received' : 'fresh')
                        }
                    />
                )}
                {notice && (
                    <Alert color="red" role="status">
                        {t(notice)}
                    </Alert>
                )}
                <VerificationFields
                    level={level}
                    onLevel={(value) => {
                        setLevel(value);
                        resetResult();
                        clearInputs();
                    }}
                    checked={validateIdentity}
                    onChecked={(value) => {
                        setValidateIdentity(value);
                        resetResult();
                    }}
                    producer={producer}
                    onProducer={(value) => {
                        setProducer(value);
                        setProducerSource('user');
                        resetResult();
                    }}
                    reported={producerSource === 'reported'}
                    disabled={locked}
                    {...(view === 'auditlogs'
                        ? {
                              auditScope: scope,
                              onAuditScope: (value: 'complete' | 'captured-prefix') => {
                                  setScope(value);
                                  setProtection(null);
                                  resetResult();
                              },
                          }
                        : {})}
                >
                    {(managed || optionsOpen) && (
                        <LocalKeyFields
                            input={keyInput}
                            form={form}
                            id={inputID}
                            passwordID={passwordID}
                            revision={keyRevision}
                            candidate={candidate}
                            onCandidate={setCandidate}
                            disabled={locked}
                            cached={cached}
                        />
                    )}
                </VerificationFields>
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
            <EvidenceDetailsDialog
                open={active && details}
                onClose={() => setDetails(false)}
                disabled={locked}
                retryDisabled={locked || remoteDisabled}
                state={{
                    operationDetails,
                    notice,
                    errorCode,
                    failedStage,
                    phase,
                    verificationFailure,
                    success,
                    metadata,
                    protection,
                    recordingInfo,
                    used,
                }}
                changeSettings={
                    received
                        ? () => {
                              setDetails(false);
                              clearInputs();
                              setOptionsOpen(true);
                          }
                        : null
                }
                retryOpen={
                    notice && received === null && opened
                        ? () => {
                              setDetails(false);
                              void open(opened, selection ?? undefined);
                          }
                        : null
                }
            >
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
            </EvidenceDetailsDialog>
        </section>
    );
}
