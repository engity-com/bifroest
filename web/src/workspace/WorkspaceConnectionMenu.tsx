import AddIcon from '@mui/icons-material/Add';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import LoginIcon from '@mui/icons-material/Login';
import { ActionIcon, Menu } from '../ui/material';
import { t } from '../ui/messages';
import type { WorkspaceController } from './controller';
import { maximumTabs, type WorkspaceState } from './model';
import type { workspacePolicy } from './policy';

export function WorkspaceConnectionMenu({
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
    const available = state.tabs
        .filter(
            (tab, index, tabs) => tabs.findIndex((entry) => entry.access === tab.access) === index,
        )
        .filter(
            (tab) => tab.access.status() === 'active' && tab.access.snapshot().terminalAvailable,
        );
    return (
        <Menu
            position="bottom-start"
            opened={state.menu?.kind === 'new'}
            onChange={(opened) => {
                if (opened) {
                    controller.openNewMenu();
                } else {
                    controller.closeNewMenu();
                }
            }}
        >
            <Menu.ContextMenu>
                <ActionIcon.Group className="connection-add">
                    <ActionIcon
                        variant="subtle"
                        color="gray"
                        size="lg"
                        aria-label={t('connectionNew')}
                        disabled={policy.addBlocked}
                        title={t('connectionNew')}
                        onClick={() => controller.newConnection()}
                    >
                        <AddIcon />
                    </ActionIcon>
                    <Menu.Target>
                        <ActionIcon
                            variant="subtle"
                            color="gray"
                            size="lg"
                            aria-label={t('connectionOptions')}
                            disabled={policy.optionsBlocked}
                        >
                            <ArrowDropDownIcon />
                        </ActionIcon>
                    </Menu.Target>
                </ActionIcon.Group>
            </Menu.ContextMenu>
            <Menu.Dropdown>
                <Menu.Item
                    icon={<AddIcon fontSize="small" />}
                    disabled={blocked || state.tabs.length >= maximumTabs}
                    onClick={() => controller.newConnection()}
                >
                    {t('connectionNew')}
                </Menu.Item>
                {available.length > 0 && <Menu.Label>{t('connectionAvailable')}</Menu.Label>}
                {available.map((tab) => (
                    <Menu.Item
                        key={tab.id}
                        icon={<LoginIcon fontSize="small" />}
                        disabled={blocked || state.tabs.length >= maximumTabs}
                        onClick={() => controller.duplicate(tab.id)}
                    >
                        {tab.scope.slug || '/'} · {tab.access.snapshot().principal}
                        {available.filter(
                            (entry) =>
                                entry.scope.slug === tab.scope.slug &&
                                entry.access.snapshot().principal ===
                                    tab.access.snapshot().principal,
                        ).length > 1 && <span className="subtle"> #{tab.id}</span>}
                    </Menu.Item>
                ))}
            </Menu.Dropdown>
        </Menu>
    );
}
