import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import type { GridWork } from '../ui/GridWork';
import { EvidenceError } from './evidence-protocol';
import { readEvidenceKey } from './local-key-input';
import type { RecordingVerificationDialogsProps } from './RecordingVerificationDialogs';
import type { LocalRecordingIndex } from './recording-index';
import {
    type SourceVerificationResult,
    verifyRecordingSource,
} from './recording-source-verification';
import { useArtifactSecrets } from './session-secrets';
import { validSigningID } from './signing-id';

export function useRecordingVerification({
    access,
    source,
    producerId = '',
    active,
    disabled,
}: {
    access: WebAccess;
    source: string;
    producerId?: string;
    active: boolean;
    disabled: boolean;
}) {
    const secrets = useArtifactSecrets(access);
    const controller = useRef<AbortController | null>(null);
    const generation = useRef(0);
    const owner = useRef({ access, source });
    owner.current = { access, source };
    const [stateOwner, setStateOwner] = useState({ access, source });
    const ownedState = stateOwner.access === access && stateOwner.source === source;
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<Progress | null>(null);
    const [result, setResult] = useState<SourceVerificationResult | null>(null);
    const [failed, setFailed] = useState('');
    const [localIndex, setLocalIndex] = useState<LocalRecordingIndex | null>(null);
    const [revealIndex, setRevealIndex] = useState<LocalRecordingIndex | null>(null);
    const revealWanted = useRef(false);
    const [used, setUsed] = useState<{ producer: string; reported: boolean } | null>(null);
    const [optionsOpen, setOptionsOpen] = useState(false);
    const [detailsOpen, setDetailsOpen] = useState(false);
    const [level, setLevel] = useState<'outer' | 'private'>('private');
    const [producer, setProducer] = useState('');
    const [checked, setChecked] = useState(false);
    const [reported, setReported] = useState(true);
    const seeded = useRef('');
    const file = useRef<HTMLInputElement>(null);
    const form = useRef<HTMLFormElement>(null);
    const [candidate, setCandidate] = useState(false);
    const [revision, setRevision] = useState(0);
    const inputID = useId();
    const passwordID = useId();
    const clearInputs = useCallback(() => {
        if (file.current) {
            file.current.value = '';
        }
        const password = form.current?.querySelector<HTMLInputElement>(
            '[name="evidence-passphrase"]',
        );
        if (password) {
            password.value = '';
        }
        setCandidate(false);
        setRevision((value) => value + 1);
    }, []);
    // biome-ignore lint/correctness/useExhaustiveDependencies: Actor/source boundaries retire the entire owned job, never resume a previous source.
    useEffect(() => {
        generation.current++;
        setBusy(false);
        setProgress(null);
        setResult(null);
        setFailed('');
        setLocalIndex(null);
        setRevealIndex(null);
        revealWanted.current = false;
        setUsed(null);
        setOptionsOpen(false);
        setDetailsOpen(false);
        setLevel('private');
        setProducer('');
        setChecked(false);
        setReported(true);
        seeded.current = '';
        clearInputs();
        setStateOwner({ access, source });
        return () => {
            generation.current++;
            controller.current?.abort();
            controller.current = null;
        };
    }, [access, source]);
    useEffect(() => {
        if (owner.current.access !== access || owner.current.source !== source) {
            return;
        }
        if (reported && validSigningID(producerId) && seeded.current !== producerId) {
            seeded.current = producerId;
            setProducer(producerId);
            setChecked(true);
        }
    }, [producerId, reported, access, source]);
    useEffect(() => {
        if (!active || disabled) {
            controller.current?.abort();
            revealWanted.current = false;
            setOptionsOpen(false);
            clearInputs();
        }
    }, [active, disabled, clearInputs]);

    async function verify() {
        if (
            !ownedState ||
            !active ||
            disabled ||
            !source ||
            controller.current ||
            (checked && !validSigningID(producer))
        ) {
            return;
        }
        const stopped = new AbortController();
        const token = ++generation.current;
        controller.current = stopped;
        setBusy(true);
        setUsed({ producer: checked ? producer : '', reported });
        setLocalIndex(null);
        setRevealIndex(null);
        setFailed('');
        setResult(null);
        setProgress(null);
        const selectedKey = file.current?.files?.[0];
        const password =
            form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ??
            '';
        const owned = () =>
            token === generation.current &&
            owner.current.access === access &&
            owner.current.source === source &&
            access.status() !== 'closed';
        try {
            const chosen = await readEvidenceKey(selectedKey, password, stopped.signal);
            const completed = await verifyRecordingSource(
                { source, level, producer: checked ? producer : '', reported, key: chosen },
                {
                    open: (name, signal, progress) =>
                        access.openRecordingSource(name, signal, progress),
                    keys: secrets,
                    signal: stopped.signal,
                    current: owned,
                    progress: setProgress,
                },
            );
            if (owned() && !stopped.signal.aborted) {
                const index = completed.index;
                setLocalIndex(index);
                setRevealIndex(revealWanted.current ? index : null);
                setResult(completed.result);
            }
        } catch (error) {
            if (owned() && !stopped.signal.aborted) {
                setFailed(
                    error instanceof EvidenceError || error instanceof RememberMeError
                        ? error.code
                        : 'unavailable',
                );
            }
        } finally {
            revealWanted.current = false;
            if (owned()) {
                clearInputs();
            }
            if (controller.current === stopped) {
                controller.current = null;
            }
            if (owned()) {
                setBusy(false);
            }
        }
    }
    const work: GridWork = {
        mode:
            ownedState && busy ? 'cancel' : ownedState && (result || failed) ? 'server' : 'verify',
        disabled: disabled || !active || !source || !ownedState,
        progress: ownedState ? progress : null,
        result: ownedState ? (result ? 'success' : failed ? 'failure' : undefined) : undefined,
        onStatusClick: () => setDetailsOpen(true),
        onClick: () => {
            if (busy) {
                controller.current?.abort();
            } else if (result || failed) {
                setResult(null);
                setFailed('');
                setLocalIndex(null);
                setRevealIndex(null);
                revealWanted.current = false;
                setUsed(null);
                setDetailsOpen(false);
            } else {
                revealWanted.current = false;
                clearInputs();
                setOptionsOpen(true);
            }
        },
    };
    const dialogs: RecordingVerificationDialogsProps = {
        options: {
            open: optionsOpen && active && !disabled && ownedState,
            source,
            kind: 'recordings',
            disabled: busy || !source || (checked && !validSigningID(producer)),
            onClose: () => {
                revealWanted.current = false;
                setOptionsOpen(false);
                clearInputs();
            },
            onStart: () => {
                setOptionsOpen(false);
                void verify();
            },
        },
        fields: {
            level,
            onLevel: (value) => {
                setLevel(value);
                clearInputs();
            },
            checked,
            onChecked: setChecked,
            producer,
            onProducer: (value) => {
                setProducer(value);
                setReported(false);
            },
            reported,
            disabled: busy,
        },
        keyFields: {
            input: file,
            form,
            id: inputID,
            passwordID,
            revision,
            candidate,
            onCandidate: setCandidate,
            disabled: busy,
            cached: secrets.fingerprint() !== null,
        },
        details: {
            open: detailsOpen && active && !disabled && ownedState,
            close: () => setDetailsOpen(false),
            source,
            failed,
            result,
            used,
        },
    };
    return {
        work,
        dialogs,
        localIndex: ownedState ? localIndex : null,
        revealIndex: ownedState ? revealIndex : null,
        openPrivate: () => {
            if (active && !disabled && !busy) {
                revealWanted.current = true;
                setLevel('private');
                clearInputs();
                setOptionsOpen(true);
            }
        },
    };
}
