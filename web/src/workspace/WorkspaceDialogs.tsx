import { ConnectionSettings } from '../terminal/ConnectionSettings';
import { Button, Modal } from '../ui/material';
import { t } from '../ui/messages';
import type { WorkspaceController } from './controller';
import type { WorkspaceState } from './model';
import type { workspacePolicy } from './policy';

export function WorkspaceDialogs({
    state,
    controller,
    policy,
    blocked,
}: {
    state: WorkspaceState;
    controller: WorkspaceController;
    policy: ReturnType<typeof workspacePolicy>;
    blocked: boolean;
}) {
    const closing = state.tabs.find((tab) => tab.id === state.closing);
    const settings = state.tabs.find((tab) => tab.id === state.settings);
    const settingsActions = settings ? controller.settingsActions(settings.id) : null;
    return (
        <>
            {settings && settingsActions && policy.settingsVisible && (
                <ConnectionSettings
                    key={settings.id}
                    access={settings.access}
                    signal={settings.signal}
                    actions={settingsActions}
                    onClose={() => controller.closeSettings()}
                />
            )}
            <Modal
                opened={state.copyLink !== null}
                onClose={() => controller.closeCopyLink()}
                title={t('connectionCopyPermanentLink')}
            >
                <input
                    aria-label={t('connectionCopyPermanentLink')}
                    value={state.copyLink ?? ''}
                    readOnly
                    onFocus={(event) => event.currentTarget.select()}
                />
            </Modal>
            <Modal
                opened={state.closing !== null && !blocked}
                onClose={() => controller.cancelClose()}
                title={t(
                    closing?.kind === 'management' ? 'managementCloseTitle' : 'terminalCloseTitle',
                )}
                closeOnClickOutside={false}
                lockScroll={false}
            >
                {closing && (
                    <p>
                        {t(closing.kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')}{' '}
                        {closing.id} · {closing.scope.slug || '/'} ·{' '}
                        {closing.access.snapshot().principal}
                    </p>
                )}
                <p>
                    {t(
                        closing?.kind === 'management'
                            ? 'managementCloseWarning'
                            : 'terminalCloseWarning',
                    )}
                </p>
                <div className="actions">
                    <Button
                        color="red"
                        disabled={!policy.closeAllowed}
                        onClick={() => controller.confirmClose()}
                    >
                        {t(closing?.kind === 'management' ? 'close' : 'terminalCloseConfirm')}
                    </Button>
                    <Button variant="default" onClick={() => controller.cancelClose()}>
                        {t('cancel')}
                    </Button>
                </div>
            </Modal>
            <Modal
                opened={state.limit}
                onClose={() => controller.dismissLimit()}
                title={t('terminalTabs')}
                lockScroll={false}
            >
                <p>{t('terminalTabLimit')}</p>
            </Modal>
        </>
    );
}
