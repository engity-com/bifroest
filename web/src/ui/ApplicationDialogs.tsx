import type { Scope } from '../remember';
import { type ApplicationNotice, NoticeBody } from './ApplicationNotice';
import { Alert, Button, Modal, Stack, Text } from './material';
import { t } from './messages';

export function BulkConfirmationDialog({
    action,
    disabled,
    onClose,
    onConfirm,
}: {
    action: 'close' | 'reset' | null;
    disabled: boolean;
    onClose(): void;
    onConfirm(): void;
}) {
    return (
        <Modal
            lockScroll={false}
            opened={action !== null}
            onClose={onClose}
            title={t(action === 'close' ? 'closeAllSessions' : 'resetAllSettings')}
        >
            <div className="stack">
                <p>
                    {t(action === 'close' ? 'closeAllSessionsConfirm' : 'resetAllSettingsConfirm')}
                </p>
                <div className="actions">
                    <Button color="red" disabled={disabled} onClick={onConfirm}>
                        {t('bulkConfirmAction')}
                    </Button>
                    <Button variant="default" onClick={onClose}>
                        {t('cancel')}
                    </Button>
                </div>
            </div>
        </Modal>
    );
}

export function SavedAccessConfirmationDialog({
    action,
    scope,
    onClose,
    onConfirm,
}: {
    action: 'local' | 'revoke' | null;
    scope: Scope | undefined;
    onClose(): void;
    onConfirm(): void;
}) {
    return (
        <Modal
            classNames={{ content: 'confirmation-dialog' }}
            lockScroll={false}
            opened={action !== null}
            onClose={onClose}
            title={t(action === 'local' ? 'removeTitle' : 'forgetTitle')}
            closeButtonProps={{ 'aria-label': t('close') }}
        >
            <Text size="sm" c="dimmed">
                {scope?.origin}/{scope?.slug}
            </Text>
            <p>{t(action === 'local' ? 'removeWarning' : 'forgetWarning')}</p>
            <div className="actions">
                <Button color="red" onClick={onConfirm}>
                    {t(action === 'local' ? 'removeLocalOnly' : 'revoke')}
                </Button>
                <Button variant="default" onClick={onClose}>
                    {t('cancel')}
                </Button>
            </div>
        </Modal>
    );
}

export function ApplicationNoticeDialog({
    opened,
    notice,
    logoutPending,
    logoutDisabled,
    onClose,
    onLogout,
}: {
    opened: boolean;
    notice: ApplicationNotice | null;
    logoutPending: boolean;
    logoutDisabled: boolean;
    onClose(): void;
    onLogout: (() => void) | undefined;
}) {
    return (
        <Modal
            lockScroll={false}
            opened={opened}
            onClose={onClose}
            title={t('showNotice')}
            closeButtonProps={{ 'aria-label': t('close') }}
        >
            {notice && (
                <Stack
                    gap="sm"
                    className="access-notice"
                    data-access-principal={notice.context?.principal}
                >
                    {notice.context && (
                        <Text size="sm" c="dimmed">
                            {notice.context.scope.slug || '/'} · {notice.context.principal}
                        </Text>
                    )}
                    <Alert role="status" color={notice.color}>
                        <NoticeBody notice={notice} />
                    </Alert>
                    {onLogout && (
                        <Button
                            color="red"
                            variant="light"
                            disabled={logoutDisabled}
                            onClick={onLogout}
                        >
                            {t(logoutPending ? 'retryLogout' : 'logout')}
                        </Button>
                    )}
                </Stack>
            )}
        </Modal>
    );
}
