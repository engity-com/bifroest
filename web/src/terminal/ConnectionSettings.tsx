import { useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Modal, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import { saveKeepAlivePreference } from '../ui/preferences';
import type { ConnectionActions } from './connection-actions';
import { keepAliveDuration } from './keepalive';

export function ConnectionSettings({
    access,
    actions,
    signal,
    onClose,
}: {
    access: WebAccess;
    actions: ConnectionActions;
    signal: AbortSignal;
    onClose: () => void;
}) {
    const [policy, setPolicy] = useState(actions.keepAliveSettings);
    const [interval, setInterval] = useState(policy.interval);
    const [busy, setBusy] = useState(false);
    const [failed, setFailed] = useState(false);
    const disposed = useRef(false);
    useEffect(() => {
        disposed.current = false;
        return () => {
            disposed.current = true;
        };
    }, []);
    async function apply() {
        if (busy || policy.locked || signal.aborted || keepAliveDuration(interval) === null) {
            return;
        }
        setBusy(true);
        setFailed(false);
        try {
            const applied = await actions.setKeepAlive(interval);
            if (disposed.current || signal.aborted) {
                return;
            }
            setPolicy(applied);
            setInterval(applied.interval);
            if (!applied.locked) {
                saveKeepAlivePreference(access.snapshot().scope, applied.interval);
                onClose();
            }
        } catch (error) {
            if (!disposed.current && !signal.aborted) {
                reportUiError('terminal', error, 'configuration');
                setFailed(true);
            }
        } finally {
            if (!disposed.current) {
                setBusy(false);
            }
        }
    }
    return (
        <Modal
            opened
            title={t('connectionSettings')}
            onClose={() => {
                if (!busy) {
                    onClose();
                }
            }}
            closeOnEscape={!busy}
            closeOnClickOutside={false}
            withCloseButton={!busy}
            lockScroll={false}
        >
            <form
                method="dialog"
                className="stack"
                onSubmit={(event) => {
                    event.preventDefault();
                    void apply();
                }}
            >
                <p className="identifier">
                    {access.snapshot().scope.slug || '/'} · {access.snapshot().principal}
                </p>
                <TextInput
                    label={t('keepAliveInterval')}
                    aria-label={t('keepAliveInterval')}
                    value={interval}
                    onChange={(event) => setInterval(event.currentTarget.value)}
                    disabled={busy || policy.locked}
                    required
                    maxLength={64}
                />
                <p className="caption">{t('keepAliveHelp')}</p>
                {policy.locked && <Alert color="blue">{t('keepAliveLocked')}</Alert>}
                {failed && (
                    <Alert role="status" color="red">
                        {t('keepAliveFailed')}
                    </Alert>
                )}
                <div className="actions">
                    <Button variant="default" disabled={busy} onClick={onClose}>
                        {t('cancel')}
                    </Button>
                    <Button
                        type="submit"
                        disabled={busy || policy.locked || keepAliveDuration(interval) === null}
                    >
                        {t('keepAliveApply')}
                    </Button>
                </div>
            </form>
        </Modal>
    );
}
