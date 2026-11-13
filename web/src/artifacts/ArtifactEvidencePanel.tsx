import {
    useCallback,
    useContext,
    useEffect,
    useEffectEvent,
    useImperativeHandle,
    useMemo,
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
import { bookmarkPath } from '../ui/hash-route';
import { relationFlow } from '../ui/ManagementJump';
import { ManagementNotFound } from '../ui/ManagementNotFound';
import type { ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert } from '../ui/material';
import { type Message, t } from '../ui/messages';
import { profileResetEvent } from '../ui/profile-reset';
import { ArtifactCatalog } from './ArtifactCatalog';
import { ArtifactOpenByID } from './ArtifactOpenByID';
import { AuditCatalog } from './AuditCatalog';
import { AuditEvidenceView } from './AuditEvidenceView';
import { AuditSourceContext } from './AuditSourceContext';
import { useAuditView } from './AuditViewContext';
import type { AuditEventRow } from './audit-events';
import { EvidenceDialogs } from './EvidenceDialogs';
import { EvidenceVerificationToolbar } from './EvidenceVerificationToolbar';
import type { EvidenceFailure, SigningExpectation as UsedExpectation } from './evidence-details';
import { EvidenceDocument } from './evidence-document';
import { EvidenceJob } from './evidence-job';
import { EvidenceError, type EvidenceMetadata } from './evidence-protocol';
import type { ArtifactEvidencePanelProps, ArtifactPhase as Phase } from './evidence-view';
import { LocalArtifactDownload } from './local-download';
import { readEvidenceKey } from './local-key-input';
import { inspectProtection } from './protection';
import { type ArtifactRequest, artifactFields, type ReceivedArtifact } from './protocol';
import { RecordingEvidenceView } from './RecordingEvidenceView';
import { type LocalRecordingIndex, recordingVerificationFromIndex } from './recording-index';
import { prepareRecordingPreview } from './recording-preview';
import { RecordingRuntimeOwner } from './recording-runtime-owner';
import { ArtifactSecretsBoundary, useArtifactSecrets } from './session-secrets';
import { validSigningID } from './signing-id';
import { useLocalKeyInput } from './use-local-key-input';
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

export function ArtifactEvidencePanel(props: ArtifactEvidencePanelProps) {
    return (
        <ArtifactSecretsBoundary access={props.access}>
            <OwnedArtifactEvidencePanel {...props} />
        </ArtifactSecretsBoundary>
    );
}
function OwnedArtifactEvidencePanel({
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
    const auditView = useAuditView();
    const sourceHints = useContext(AuditSourceContext);
    const managed = mode === 'audit-verification';
    const secrets = useArtifactSecrets(access);
    const cacheRevision = secrets.getSnapshot().revision;
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
    const document = useMemo(
        () =>
            new EvidenceDocument(
                (request) =>
                    !disabled &&
                    access.status() !== 'closed' &&
                    request.kind === (view === 'recordings' ? 'recording' : 'audit'),
            ),
        [access, disabled, view],
    );
    const { opened, selection, received, protection, recordingInfo, playback, receipt } =
        useSyncExternalStore(document.subscribe, document.getSnapshot);
    const updateReceipt = document.updateReceipt;
    const { recordingFlow, recordingSession, verified, auditIndex, verifiedSensitive, used } =
        receipt;
    const [auditEvent, setAuditEvent] = useState<AuditEventRow | null>(null);
    const verificationKey = useLocalKeyInput();
    const decryptionKey = useLocalKeyInput();
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
    const [decryptOpen, setDecryptOpen] = useState(false);
    const job = useMemo(
        () => new EvidenceJob(() => document.getSnapshot().opened !== null),
        [document],
    );
    const { phase, progress } = useSyncExternalStore(job.subscribe, job.getSnapshot);
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
    const candidate = verificationKey.fields.candidate;
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
    const appliedSensitive = useRef(effectiveSensitive);
    const [auditlog, setAuditlog] = useState('');
    const [id, setID] = useState('');
    const heading = useRef<HTMLDivElement | null>(null);
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
        appliedSensitive.current = effectiveSensitive;
        retireRecordingRuntime();
        setOptionsOpen(false);
        job.retire();
        downloads.current.clear();
        clearInputs();
        document.close();
        attemptedVerification.current = false;
        setDecryptOpen(false);
        seeded.current = '';
        expectedSource.current = '';
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
        verificationKey.clear();
        decryptionKey.clear();
    };
    const cancelJob = () => {
        appliedSensitive.current = effectiveSensitive;
        job.cancel();
    };
    const cancelFromOutside = useEffectEvent(() => {
        cancelJob();
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
        appliedSensitive.current = effectiveSensitive;
        retireRecordingRuntime();
        job.retire();
        downloads.current.clear();
        document.close();
        consumedRoute.current = null;
        consumedSelection.current = null;
        returnRoute.current = null;
        routedSummary.current = null;
        setAuditEvent(null);
        attemptedVerification.current = false;
        setDecryptOpen(false);
        seeded.current = '';
        expectedSource.current = '';
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
            document.close();
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
                cancelJob();
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
                progress: (value) => job.progress(token, value),
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
        const chosen = managed ? verificationKey.read() : null;
        const chosenFile = chosen?.file;
        const chosenPassphrase = chosen?.passphrase ?? '';
        resetResult();
        retireRecordingRuntime();
        attemptedVerification.current = false;
        if (!managed) {
            clearInputs();
        }
        document.open(request, summary);
        setDecryptOpen(false);
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
                    job.progress(token, value);
                }
            };
            const image = await access.downloadArtifact(request, signal, report);
            if (!current(token, signal)) {
                return;
            }
            if (!matchesRoute(request)) {
                throw new EvidenceError('cancelled');
            }
            document.receive(image);
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
            document.inspect(header);
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
        const { file, passphrase } = verificationKey.read();
        const expected = identity();
        if (!(managed && auditView?.local)) {
            resetResult();
        }
        updateReceipt({ type: 'expectation', value: expected });
        const hadPlayback = playback !== null;
        if (image.request.kind === 'recording') {
            document.clearPlayback();
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
                                  job.progress(token, value);
                              }
                          })));
                if (!current(token, signal)) {
                    return;
                }
                if ('validation' in header) {
                    document.inspect(header as EvidenceMetadata);
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
        job.progress(token, null);
        const runtime = await runtimeFor(image, signal);
        const result = await prepareRecordingPreview(runtime, image, key, {
            signal,
            current: () => current(token, signal),
            target: () => routeRef.current,
            keys: secrets,
            information: document.information,
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
            document.preview(result.source, result.image);
        }
    }
    async function decodeRecording() {
        if (!received) {
            return;
        }
        const image = received;
        const { file, passphrase } = decryptionKey.read();
        await run('preparing', async (signal, token) => {
            let key = recordingInfo?.encrypted ? secrets.matching(recordingInfo.recipient) : null;
            if (file) {
                key = await readEvidenceKey(file, passphrase, signal);
            }
            document.clearPlayback();
            await prepareRecording(image, key, signal, token);
        });
    }
    function closeLocal() {
        appliedSensitive.current = effectiveSensitive;
        retireRecordingRuntime();
        job.retire();
        resetResult();
        clearInputs();
        document.close();
        setDecryptOpen(false);
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
                    document.clearPlayback();
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
            cancelJob();
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
    const applySensitive = useEffectEvent(() => {
        if (appliedSensitive.current !== effectiveSensitive) {
            if (view === 'auditlogs' && received !== null && job.busy) {
                return; // Retain the explicit intent until this owned job settles.
            }
            appliedSensitive.current = effectiveSensitive;
            if (view === 'auditlogs' && received !== null) {
                if (!managed || auditView?.local) {
                    void recheck();
                } else {
                    resetResult();
                }
            }
        }
    });
    // biome-ignore lint/correctness/useExhaustiveDependencies: Completion may wake a queued explicit eye change; only a changed actor/source-owned intent can reproject existing bytes. Cancel/source retirement consume it; phase changes alone never retry work.
    useEffect(() => {
        applySensitive();
    }, [effectiveSensitive, phase, received]);
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
        <EvidenceVerificationToolbar
            result={
                success || verificationFailure || flowMismatch
                    ? success && !verificationFailure
                        ? 'success'
                        : 'failure'
                    : null
            }
            busy={phase !== null}
            disabled={locked}
            verifyDisabled={disabled || (!phase && received === null)}
            showVerify={
                !success ||
                attemptedVerification.current ||
                verificationFailure !== null ||
                flowMismatch ||
                phase !== null
            }
            onDetails={() => {
                setOperationDetails(false);
                setDetails(true);
            }}
            onCancel={() => {
                cancelJob();
                clearInputs();
            }}
            onVerify={() => {
                if (
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
        />
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
                    {view === 'recordings' ? (
                        <RecordingEvidenceView
                            received={received}
                            summary={selection}
                            info={recordingInfo}
                            playback={playback}
                            phase={phase}
                            progress={progress}
                            notice={notice}
                            disabled={disabled}
                            locked={locked}
                            active={active && (!managed || auditView?.local === true)}
                            showPlaceholder={!managed}
                            playbackAllowed={
                                !(
                                    recordingInfo &&
                                    ((route?.flow && route.flow !== recordingInfo.flow) ||
                                        (route?.sessionId &&
                                            !uuidEqual(route.sessionId, recordingInfo.sessionId)))
                                )
                            }
                            verificationControls={verificationControls}
                            scope={access.snapshot().scope}
                            relation={{ flow: recordingFlow, sessionId: recordingSession }}
                            page={filePage}
                            onPage={setFilePage}
                            onSave={save}
                            onOpen={() => {
                                void decodeRecording();
                            }}
                            onOperationDetails={() => {
                                setOperationDetails(true);
                                setDetails(true);
                            }}
                        />
                    ) : (
                        received && (
                            <AuditEvidenceView
                                verified={verified}
                                index={auditIndex}
                                privateFieldsKnown={verifiedSensitive && effectiveSensitive}
                                active={active && (!managed || auditView?.local === true)}
                                selected={auditEvent}
                                onSelect={setAuditEvent}
                            />
                        )
                    )}
                </>
            )}
            <EvidenceDialogs
                notice={notice}
                locked={locked}
                source={{
                    received,
                    summary: selection,
                    page: filePage,
                    onPage: setFilePage,
                    onSave: save,
                }}
                decryption={{
                    open: active && decryptOpen,
                    key: decryptionKey.fields,
                    close: () => {
                        setDecryptOpen(false);
                        clearInputs();
                    },
                    unlock: () => {
                        setDecryptOpen(false);
                        void decodeRecording();
                    },
                }}
                verification={{
                    open: active && optionsOpen,
                    source: opened?.auditlog ?? route?.auditlog ?? '',
                    kind: view === 'auditlogs' ? 'audit' : 'recording',
                    disabled:
                        locked ||
                        !pinReady ||
                        (received === null
                            ? remoteDisabled || !managed || !route?.auditlog
                            : !ready),
                    input: managed && received ? verificationInput : null,
                    selectInput: setVerificationInput,
                    settings: {
                        level,
                        checked: validateIdentity,
                        producer,
                        reported: producerSource === 'reported',
                        onLevel: (value) => {
                            setLevel(value);
                            resetResult();
                            clearInputs();
                        },
                        onChecked: (value) => {
                            setValidateIdentity(value);
                            resetResult();
                        },
                        onProducer: (value) => {
                            setProducer(value);
                            setProducerSource('user');
                            resetResult();
                        },
                        ...(view === 'auditlogs'
                            ? {
                                  auditScope: scope,
                                  onAuditScope: (value: 'complete' | 'captured-prefix') => {
                                      setScope(value);
                                      document.forgetProtection();
                                      resetResult();
                                  },
                              }
                            : {}),
                    },
                    key: verificationKey.fields,
                    showKey: managed || optionsOpen,
                    cached,
                    canForget: secrets.fingerprint() !== null,
                    canReplace: encrypted && verified !== null,
                    export:
                        !flowMismatch && verified?.output
                            ? {
                                  data: verified.output,
                                  filename:
                                      verified.request.kind === 'recording'
                                          ? `recording-${verified.request.id}.cast`
                                          : `audit-${verified.request.auditlog}.jsonl`,
                              }
                            : null,
                    forget: () => secrets.clear(),
                    replace: () => {
                        resetResult();
                        verificationKey.clearCandidate();
                    },
                    close: () => {
                        setOptionsOpen(false);
                        clearInputs();
                    },
                    start: () => {
                        setOptionsOpen(false);
                        if (managed && verificationInput === 'fresh' && route?.auditlog) {
                            void open({ kind: 'audit', auditlog: route.auditlog });
                        } else if (received) {
                            void recheck();
                        } else if (route?.auditlog) {
                            void open({ kind: 'audit', auditlog: route.auditlog });
                        }
                    },
                }}
                details={{
                    open: active && details,
                    retryDisabled: locked || remoteDisabled,
                    close: () => setDetails(false),
                    state: {
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
                    },
                    changeSettings: received
                        ? () => {
                              setDetails(false);
                              clearInputs();
                              setOptionsOpen(true);
                          }
                        : null,
                    retryOpen:
                        notice && received === null && opened
                            ? () => {
                                  setDetails(false);
                                  void open(opened, selection ?? undefined);
                              }
                            : null,
                }}
            />
        </section>
    );
}
