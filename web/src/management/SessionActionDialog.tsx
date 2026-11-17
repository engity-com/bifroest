import type { AccessSnapshot } from '../remember';
import { Alert, Button, Modal, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import type { ActionPreview } from './action';
import { sessionOwnerLabel, sessionTime } from './session-display';

export function SessionActionDialog({
    owner,
    active,
    preview,
    typed,
    busy,
    sending,
    disabled,
    onType,
    onClose,
    onConfirm,
    onCancel,
}: {
    owner: AccessSnapshot;
    active: boolean;
    preview: ActionPreview | null;
    typed: string;
    busy: boolean;
    sending: boolean;
    disabled: boolean;
    onType(value: string): void;
    onClose(): void;
    onConfirm(): void;
    onCancel(): void;
}) {
    return (
        <Modal
            classNames={{ content: 'confirmation-dialog' }}
            lockScroll={false}
            opened={active && preview !== null}
            onClose={onClose}
            closeOnClickOutside={false}
            closeOnEscape={!sending}
            withCloseButton={!sending}
            title={t('managementConfirmTitle')}
        >
            {preview !== null && (
                <form
                    method="dialog"
                    className="stack"
                    onSubmit={(event) => {
                        event.preventDefault();
                        onConfirm();
                    }}
                >
                    <p>
                        {owner.scope.slug || '/'} · {owner.principal}
                    </p>
                    <Alert color={preview.action === 'dispose' ? 'red' : 'yellow'}>
                        {t(
                            preview.action === 'dispose'
                                ? 'managementDisposeWarning'
                                : 'managementDisconnectWarning',
                        )}
                    </Alert>
                    <p>
                        {preview.target.flow}/{preview.target.id}
                    </p>
                    {preview.target.details === undefined ? (
                        <Alert color="yellow">{t('managementActionNoDetails')}</Alert>
                    ) : (
                        <>
                            <p>{sessionOwnerLabel(preview.target.details)}</p>
                            <p>
                                {t('managementCreated')}:{' '}
                                {sessionTime(preview.target.details.createdAt)}
                            </p>
                        </>
                    )}
                    <p>
                        {t('managementConfirmationExpires')}: {sessionTime(preview.expiresAt)}
                    </p>
                    <TextInput
                        label={t('managementConfirmTarget')}
                        value={typed}
                        onChange={(event) => onType(event.currentTarget.value)}
                        disabled={busy}
                        autoComplete="off"
                    />
                    <div className="actions">
                        <Button
                            type="submit"
                            color="red"
                            disabled={
                                disabled ||
                                busy ||
                                typed !== `${preview.target.flow}/${preview.target.id}`
                            }
                        >
                            {t('managementConfirmAction')}
                        </Button>
                        {busy ? (
                            <Button type="button" variant="default" onClick={onCancel}>
                                {t('managementStopWaiting')}
                            </Button>
                        ) : (
                            <Button type="button" variant="default" onClick={onClose}>
                                {t('cancel')}
                            </Button>
                        )}
                    </div>
                </form>
            )}
        </Modal>
    );
}
