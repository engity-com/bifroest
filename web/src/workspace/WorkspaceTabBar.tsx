import CloseIcon from '@mui/icons-material/Close';
import LoginIcon from '@mui/icons-material/Login';
import { Box, CircularProgress, IconButton, Tab, Tabs } from '@mui/material';
import type { ReactNode } from 'react';
import type { AuthenticationView } from '../terminal/authentication-view';
import { ConnectionTab } from '../terminal/ConnectionTab';
import { bookmarkPath, hashPath } from '../ui/hash-route';
import type { ManagementLocation } from '../ui/management-location';
import { t } from '../ui/messages';
import { ConnectionTabMenu } from './ConnectionTabMenu';
import type { WorkspaceController } from './controller';
import { maximumTabs, type WorkspaceState } from './model';
import type { workspacePolicy } from './policy';
import { useTabLayout } from './use-tab-layout';
import { WorkspaceConnectionMenu } from './WorkspaceConnectionMenu';

export function WorkspaceTabBar({
    state,
    controller,
    active,
    authentication,
    blocked,
    focusBlocked,
    policy,
    notice,
    utilities,
    locations,
}: {
    state: WorkspaceState;
    controller: WorkspaceController;
    active: number | null;
    authentication: AuthenticationView | null;
    blocked: boolean;
    focusBlocked: boolean;
    policy: ReturnType<typeof workspacePolicy>;
    notice: ReactNode;
    utilities: ReactNode;
    locations: ReadonlyMap<number, ManagementLocation> | undefined;
}) {
    const tabList = useTabLayout(active, state.tabs);
    const menu = state.menu;
    const menuOwner =
        menu?.kind === 'tab' ? state.tabs.find((tab) => tab.id === menu.owner) : undefined;
    const showTabMenu = (id: number, opened: boolean) => {
        if (opened) {
            controller.openTabMenu(id);
        } else {
            controller.closeTabMenu(id);
            requestAnimationFrame(() => {
                const element = document.getElementById(`terminal-tab-${id}`);
                if (element?.getAttribute('aria-selected') === 'true') {
                    element.focus();
                }
            });
        }
    };
    const copyLink = (id: number) => {
        const owner = controller.copyTarget(id);
        if (!owner) {
            return;
        }
        const url = new URL(bookmarkPath(owner.scope, locations?.get(owner.id)), owner.scope.origin)
            .href;
        void Promise.resolve()
            .then(() => navigator.clipboard.writeText(url))
            .catch(() => controller.showCopyLink(id, url));
    };
    return (
        <header className="application-bar">
            <div className="application-tabs">
                <ConnectionTabMenu
                    owner={
                        menuOwner
                            ? {
                                  principal: menuOwner.access.snapshot().principal,
                                  slug: menuOwner.scope.slug,
                                  kind: menuOwner.kind,
                                  phase: menuOwner.state.phase,
                                  inputClosed: menuOwner.inputClosed,
                              }
                            : null
                    }
                    blocked={blocked}
                    focusBlocked={focusBlocked}
                    atLimit={state.tabs.length >= maximumTabs}
                    onChange={(opened) => {
                        if (!opened && menuOwner) {
                            showTabMenu(menuOwner.id, false);
                        }
                    }}
                    actions={{
                        duplicate: () => {
                            if (menuOwner) {
                                controller.duplicate(menuOwner.id);
                            }
                        },
                        reauthenticate: () => {
                            if (menuOwner) {
                                controller.reauthenticate(menuOwner.id);
                            }
                        },
                        copyLink: () => {
                            if (menuOwner) {
                                copyLink(menuOwner.id);
                            }
                        },
                        settings: () => {
                            if (menuOwner) {
                                controller.openSettings(menuOwner.id);
                            }
                        },
                        eof: () => {
                            if (menuOwner) {
                                controller.eof(menuOwner.id);
                            }
                        },
                        signal: (value) => {
                            if (menuOwner) {
                                controller.signal(menuOwner.id, value);
                            }
                        },
                        disconnect: () => {
                            if (menuOwner) {
                                controller.disconnect(menuOwner.id);
                            }
                        },
                        logout: () => {
                            if (menuOwner) {
                                controller.logout(menuOwner.id);
                            }
                        },
                        close: () => {
                            if (menuOwner) {
                                controller.requestClose(menuOwner.id);
                            }
                        },
                    }}
                >
                    <Tabs
                        ref={tabList}
                        className="terminal-tab-list"
                        aria-label={t('connectionTabs')}
                        value={authentication ? 'authentication' : (active ?? false)}
                        variant="scrollable"
                        scrollButtons="auto"
                        allowScrollButtonsMobile
                        selectionFollowsFocus
                        onChange={(event, id: number) => {
                            // ConnectionTab owns clicks; MUI focus selection is keyboard.
                            if (event.type !== 'click') {
                                controller.select(id, false);
                            }
                        }}
                    >
                        {state.tabs.map((tab) => (
                            <ConnectionTab
                                key={tab.id}
                                id={tab.id}
                                value={tab.id}
                                href={hashPath(
                                    tab.scope,
                                    tab.routeId ?? null,
                                    locations?.get(tab.id),
                                )}
                                kind={tab.kind}
                                access={tab.access}
                                scope={tab.scope.slug}
                                principal={tab.access.snapshot().principal}
                                {...(tab.title === undefined ? {} : { title: tab.title })}
                                state={tab.state}
                                active={authentication === null && active === tab.id}
                                disabled={policy.tabSelectionBlocked}
                                onSelect={() => controller.select(tab.id)}
                                onMenu={(opened) => showTabMenu(tab.id, opened)}
                                onClose={() => controller.requestClose(tab.id)}
                            />
                        ))}
                        {authentication && (
                            <Tab
                                value="authentication"
                                component="div"
                                id="authentication-tab"
                                aria-label={`${t('authenticationTab')} ${authentication.user}`}
                                aria-controls="authentication-pane"
                                label={<AuthenticationTabLabel view={authentication} />}
                            />
                        )}
                    </Tabs>
                </ConnectionTabMenu>
                <WorkspaceConnectionMenu
                    state={state}
                    controller={controller}
                    policy={policy}
                    blocked={blocked}
                />
                <div className="workspace-utilities">
                    {notice}
                    {utilities}
                </div>
            </div>
        </header>
    );
}

function AuthenticationTabLabel({ view }: { view: AuthenticationView }) {
    return (
        <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 1 }}>
            {view.pending ? <CircularProgress size={14} /> : <LoginIcon fontSize="small" />}
            {view.user || t('login')}
            <IconButton
                component="span"
                role="button"
                size="small"
                tabIndex={-1}
                aria-label={t('cancelAuthentication')}
                onClick={(event) => {
                    event.stopPropagation();
                    view.onCancel();
                }}
            >
                <CloseIcon fontSize="small" />
            </IconButton>
        </Box>
    );
}
