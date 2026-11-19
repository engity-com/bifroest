import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlineOutlined';
import LogoutIcon from '@mui/icons-material/Logout';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useState } from 'react';
import { type ApplicationNotice, NoticeBody } from '../ui/ApplicationNotice';
import {
    type LinkMetadata,
    type LoginMethod,
    loginOptionFor,
    loginOptionKey,
} from '../ui/link-metadata';
import {
    ActionIcon,
    Alert,
    Button,
    Checkbox,
    Group,
    Menu,
    Modal,
    PasswordInput,
    SegmentedControl,
    Select,
    Stack,
    Text,
    TextInput,
    VisuallyHidden,
} from '../ui/material';
import { type Message, t } from '../ui/messages';
import { allowsSavedLogin, savedLoginChoice } from './choice';
import { DeviceLogin } from './DeviceLogin';
import type { LoginStep } from './interactive';
import { SlugInput } from './SlugInput';

export type SavedAccessState = 'loading' | 'missing' | 'ready' | 'pending' | 'unavailable';

export interface LoginDialogState {
    open: boolean;
    metadata: LinkMetadata;
    ready: boolean;
    route: {
        slug: string | null;
        origin: string | null;
        failed: boolean;
        invalid?: boolean;
        editing?: boolean;
        links: readonly string[];
    };
    saved: SavedAccessState;
    activeUsesScope: boolean;
    notice: ApplicationNotice | null;
    choice: string;
    user: string;
    optIn: boolean;
    inputRevision: number;
    busy: boolean;
    managementLocked: boolean;
    rememberUncertain: boolean;
    oidcLink?: string | null;
    device?: LoginStep | null;
    deviceReady?: boolean;
}

export interface LoginDialogActions {
    close(): void;
    chooseLink(slug: string): void;
    editLink?(editing: boolean): void;
    chooseMethod(choice: string): void;
    changeUser(user: string): void;
    changeOptIn(value: boolean): void;
    submit(form: HTMLFormElement): void;
    cancel(): void;
    resume(): void;
    confirmSaved(action: 'revoke' | 'local'): void;
    retryMetadata(): void;
    showNotice(): void;
    continueDevice?(): void;
}

const methodMessages: Record<LoginMethod, { label: Message; description: Message }> = {
    password: { label: 'loginPasswordTab', description: 'passwordMethod' },
    'keyboard-interactive': { label: 'loginInteractiveTab', description: 'interactiveMethod' },
    oidc: { label: 'loginOidcTab', description: 'oidcMethod' },
    'public-key': { label: 'loginKeyTab', description: 'keyMethod' },
    none: { label: 'loginNoneTab', description: 'noneMethod' },
};

// Presentation only. Credentials remain uncontrolled DOM inputs and are handed
// to the owning login flow only by an explicit submit, never stored as React state.
export function LoginDialog({
    state,
    actions,
}: {
    state: LoginDialogState;
    actions: LoginDialogActions;
}) {
    const option = loginOptionFor(state.metadata, state.choice);
    const savedAvailable = state.saved === 'ready' && allowsSavedLogin(state.metadata);
    const savedSelected = savedAvailable && state.choice === savedLoginChoice;
    const method = option?.method ?? null;
    const userFieldOwner = JSON.stringify([
        state.metadata.scope,
        state.choice,
        state.inputRevision,
    ]);
    const [invalidUserOwner, setInvalidUserOwner] = useState<string | null>(null);
    const userInvalid = invalidUserOwner === userFieldOwner && state.user.trim().length === 0;
    const choices = state.metadata.loginOptions.map((entry) => {
        const messages = methodMessages[entry.method];
        const multipleNameModes = state.metadata.loginOptions.some(
            (other) => other.method === entry.method && other.requestUser !== entry.requestUser,
        );
        const nameMode = multipleNameModes
            ? ` · ${t(entry.requestUser ? 'loginWithUserName' : 'loginWithoutUserName')}`
            : '';
        return {
            value: loginOptionKey(entry),
            label: (
                <>
                    <span aria-hidden="true">
                        {t(messages.label)}
                        {nameMode}
                    </span>
                    <VisuallyHidden>
                        {t(messages.description)}
                        {nameMode}
                    </VisuallyHidden>
                </>
            ),
        };
    });
    if (savedAvailable) {
        choices.unshift({ value: savedLoginChoice, label: <>{t('loginSavedTab')}</> });
    }
    const useSelect =
        state.metadata.loginOptions.length > 3 ||
        new Set(state.metadata.loginOptions.map((entry) => entry.method)).size !==
            state.metadata.loginOptions.length;
    const savedOptions = state.ready && state.saved === 'ready' && !state.activeUsesScope && (
        <Menu>
            <Menu.Target>
                <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="sm"
                    disabled={state.busy}
                    aria-label={t('savedOptions')}
                >
                    <MoreVertIcon fontSize="small" />
                </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
                <Menu.Item
                    icon={<LogoutIcon fontSize="small" />}
                    onClick={() => actions.confirmSaved('revoke')}
                >
                    {t('forgetSaved')}
                </Menu.Item>
                <Menu.Item
                    icon={<DeleteOutlineIcon fontSize="small" />}
                    onClick={() => actions.confirmSaved('local')}
                >
                    {t('removeLocalOnly')}
                </Menu.Item>
            </Menu.Dropdown>
        </Menu>
    );
    return (
        <Modal
            classNames={{ content: 'confirmation-dialog login-dialog' }}
            size="sm"
            padding="lg"
            centered
            lockScroll={false}
            opened={state.open}
            onClose={actions.close}
            closeOnClickOutside={false}
            closeOnEscape={!state.busy}
            title={t('login')}
            closeButtonProps={{ 'aria-label': t('close') }}
        >
            {state.notice && (
                <Alert role="status" color={state.notice.color}>
                    <NoticeBody notice={state.notice} />
                    {state.notice.context && (
                        <ActionIcon
                            variant="subtle"
                            color={state.notice.color}
                            onClick={actions.showNotice}
                            aria-label={t('showNotice')}
                        >
                            {state.notice.color === 'green' ? (
                                <CheckCircleIcon />
                            ) : (
                                <WarningAmberIcon />
                            )}
                        </ActionIcon>
                    )}
                </Alert>
            )}
            <Stack
                gap="sm"
                data-login-scope={state.metadata.scope.slug}
                data-login-ready={state.ready}
            >
                {!state.device?.device && (
                    <SlugInput
                        slug={state.route.slug}
                        origin={state.route.origin}
                        options={state.route.links}
                        invalid={state.route.invalid === true}
                        disabled={state.busy || state.managementLocked || state.rememberUncertain}
                        onCommit={actions.chooseLink}
                        onEditing={(editing) => actions.editLink?.(editing)}
                    />
                )}
                {state.ready && state.saved === 'pending' && (
                    <Alert color="yellow">
                        <p>{t('pending')}</p>
                        {!state.activeUsesScope && (
                            <Button
                                variant="outline"
                                disabled={state.busy}
                                onClick={() => actions.confirmSaved('local')}
                            >
                                {t('removeLocal')}
                            </Button>
                        )}
                    </Alert>
                )}
                {state.device?.device ? (
                    <DeviceLogin
                        key={`${state.inputRevision}:${state.device.sequence}:${state.device.device.userCode}`}
                        device={state.device.device}
                        ready={state.deviceReady === true}
                        onContinue={() => actions.continueDevice?.()}
                        onCancel={actions.cancel}
                    />
                ) : !state.ready &&
                  (state.route.invalid || state.route.editing) ? null : !state.ready ? (
                    <Alert
                        color={state.route.failed || state.route.origin === null ? 'red' : 'blue'}
                    >
                        <p>
                            {t(
                                state.route.failed || state.route.origin === null
                                    ? 'slugLoadFailed'
                                    : 'loadingSlug',
                            )}
                        </p>
                        {state.route.failed && state.route.origin !== null && (
                            <Button
                                variant="default"
                                disabled={
                                    state.busy || state.managementLocked || state.rememberUncertain
                                }
                                onClick={actions.retryMetadata}
                            >
                                {t('retrySlug')}
                            </Button>
                        )}
                    </Alert>
                ) : option === null && !savedSelected ? (
                    <>
                        <Alert color="blue">
                            {t(
                                state.metadata.scope.slug === '' &&
                                    state.metadata.publishedSlugs.length > 0
                                    ? 'chooseSlug'
                                    : 'noLoginMethods',
                            )}
                        </Alert>
                        {savedOptions}
                    </>
                ) : (
                    <form
                        key={`${state.metadata.scope.slug}:${state.choice}`}
                        method={
                            savedSelected ||
                            method === 'public-key' ||
                            method === 'none' ||
                            method === 'oidc'
                                ? 'dialog'
                                : 'post'
                        }
                        action={
                            savedSelected ||
                            method === 'public-key' ||
                            method === 'none' ||
                            method === 'oidc'
                                ? undefined
                                : '/api/v1/login/password'
                        }
                        className="login-form"
                        onInvalidCapture={(event) => {
                            const input = event.target;
                            if (input instanceof HTMLInputElement && input.name === 'user') {
                                event.preventDefault();
                                setInvalidUserOwner(userFieldOwner);
                                input.focus();
                            }
                        }}
                        onInput={() => {
                            if (!savedSelected) {
                                actions.chooseMethod(state.choice);
                            }
                        }}
                        onSubmit={(event) => {
                            event.preventDefault();
                            if (savedSelected) {
                                actions.resume();
                            } else {
                                if (option?.requestUser && state.user.trim().length === 0) {
                                    setInvalidUserOwner(userFieldOwner);
                                    (
                                        event.currentTarget.elements.namedItem(
                                            'user',
                                        ) as HTMLInputElement | null
                                    )?.focus();
                                    return;
                                }
                                actions.submit(event.currentTarget);
                            }
                        }}
                    >
                        {useSelect ? (
                            <Select
                                label={t('loginMethod')}
                                value={state.choice}
                                disabled={state.busy}
                                allowDeselect={false}
                                data={choices}
                                onChange={(choice) => {
                                    if (choice !== null) {
                                        actions.chooseMethod(choice);
                                    }
                                }}
                            />
                        ) : (
                            <SegmentedControl
                                aria-label={t('loginMethod')}
                                value={state.choice}
                                onChange={actions.chooseMethod}
                                disabled={state.busy}
                                fullWidth
                                data={choices}
                            />
                        )}
                        {savedSelected && <Text size="sm">{t('savedLoginHint')}</Text>}
                        {state.busy && method === 'oidc' && state.oidcLink && (
                            <Alert color="blue">
                                <a href={state.oidcLink} target="_blank" rel="noopener noreferrer">
                                    {t('oidcOpen')}
                                </a>
                            </Alert>
                        )}
                        {option?.requestUser && (
                            <TextInput
                                name="user"
                                label={t('user')}
                                aria-label={t('user')}
                                required
                                pattern={'.*\\S.*'}
                                maxLength={256}
                                value={state.user}
                                error={userInvalid}
                                helperText={userInvalid ? t('userRequired') : undefined}
                                onChange={(event) => actions.changeUser(event.currentTarget.value)}
                                autoComplete="username"
                                data-autofocus
                                disabled={state.busy}
                            />
                        )}
                        {method === 'password' && (
                            <PasswordInput
                                key={state.inputRevision}
                                name="password"
                                label={t('password')}
                                autoComplete="current-password"
                                visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
                                disabled={state.busy}
                            />
                        )}
                        {method === 'public-key' && (
                            <>
                                <Text size="xs" c="dimmed">
                                    {t('keyLocalHint')}
                                </Text>
                                <label className="stack" htmlFor="key-private">
                                    {t('keyPrivateFile')}
                                    <input
                                        key={`private:${state.inputRevision}`}
                                        id="key-private"
                                        type="file"
                                        required
                                        disabled={state.busy}
                                    />
                                </label>
                                <PasswordInput
                                    key={`passphrase:${state.inputRevision}`}
                                    id="key-passphrase"
                                    label={t('keyPassphrase')}
                                    autoComplete="off"
                                    visibilityToggleButtonProps={{
                                        'aria-label': t('togglePassword'),
                                    }}
                                    disabled={state.busy}
                                />
                                <label className="stack" htmlFor="key-certificate">
                                    {t(
                                        option?.certificateRequired
                                            ? 'keyCertificateRequired'
                                            : 'keyCertificateFile',
                                    )}
                                    <input
                                        key={`certificate:${state.inputRevision}`}
                                        id="key-certificate"
                                        type="file"
                                        required={option?.certificateRequired}
                                        disabled={state.busy}
                                    />
                                </label>
                            </>
                        )}
                        {state.saved === 'missing' &&
                            option?.rememberMe !== undefined &&
                            option.rememberMe !== 'forbidden' &&
                            option.rememberMe !== 'enforced' && (
                                <Checkbox
                                    checked={state.optIn}
                                    onChange={(event) =>
                                        actions.changeOptIn(event.currentTarget.checked)
                                    }
                                    disabled={state.busy || state.saved !== 'missing'}
                                    label={t('remember')}
                                    size="sm"
                                />
                            )}
                        <Group justify="flex-end" gap="xs">
                            {savedOptions}
                            <Button
                                type="submit"
                                loading={state.busy}
                                disabled={state.busy || state.managementLocked}
                            >
                                {t(method === 'none' ? 'noneMethod' : 'login')}
                            </Button>
                            {state.busy && (
                                <Button type="button" variant="default" onClick={actions.cancel}>
                                    {t('cancel')}
                                </Button>
                            )}
                        </Group>
                    </form>
                )}
            </Stack>
        </Modal>
    );
}
