import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlineOutlined';
import LogoutIcon from '@mui/icons-material/Logout';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
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

export type SavedAccessState = 'loading' | 'missing' | 'ready' | 'pending' | 'unavailable';

export interface LoginDialogState {
  open: boolean;
  metadata: LinkMetadata;
  ready: boolean;
  route: { slug: string | null; origin: string | null; failed: boolean; links: readonly string[] };
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
}

export interface LoginDialogActions {
  close(): void;
  chooseLink(slug: string): void;
  chooseMethod(choice: string): void;
  changeUser(user: string): void;
  changeOptIn(value: boolean): void;
  submit(form: HTMLFormElement): void;
  cancel(): void;
  resume(): void;
  confirmSaved(action: 'revoke' | 'local'): void;
  retryMetadata(): void;
  showNotice(): void;
}

const methodMessages: Record<LoginMethod, { label: Message; description: Message }> = {
  password: { label: 'loginPasswordTab', description: 'passwordMethod' },
  'keyboard-interactive': { label: 'loginInteractiveTab', description: 'interactiveMethod' },
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
  const method = option?.method ?? null;
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
  const useSelect =
    choices.length > 3 ||
    new Set(state.metadata.loginOptions.map((entry) => entry.method)).size !== choices.length;
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
              {state.notice.color === 'green' ? <CheckCircleIcon /> : <WarningAmberIcon />}
            </ActionIcon>
          )}
        </Alert>
      )}
      <Stack gap="sm" data-login-scope={state.metadata.scope.slug} data-login-ready={state.ready}>
        {state.route.links.length > 1 ? (
          <Select
            label={t('connectionLink')}
            value={
              state.route.slug !== null && state.route.links.includes(state.route.slug)
                ? state.route.slug
                : ''
            }
            data={state.route.links.map((slug) => ({ value: slug, label: slug || '/' }))}
            disabled={state.busy}
            allowDeselect={false}
            onChange={(value) => {
              if (value !== null) {
                actions.chooseLink(value);
              }
            }}
          />
        ) : (
          state.route.slug && (
            <Text size="sm" c="dimmed">
              {state.route.slug}
            </Text>
          )
        )}
        <Text size="xs" c="dimmed">
          {t('slugRouteHint')}
        </Text>
        {state.ready && state.saved === 'ready' && (
          <Group justify="space-between" gap="xs">
            <Button variant="light" size="xs" disabled={state.busy} onClick={actions.resume}>
              {t('useSaved')}
            </Button>
            {!state.activeUsesScope && (
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
            )}
          </Group>
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
        {state.ready && state.saved === 'unavailable' && (
          <Alert color="yellow">{t('storageUnavailable')}</Alert>
        )}
        {!state.ready ? (
          <Alert color={state.route.failed || state.route.origin === null ? 'red' : 'blue'}>
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
                disabled={state.busy || state.managementLocked || state.rememberUncertain}
                onClick={actions.retryMetadata}
              >
                {t('retrySlug')}
              </Button>
            )}
          </Alert>
        ) : option === null ? (
          <Alert color="blue">
            {t(
              state.metadata.scope.slug === '' && state.metadata.publishedSlugs.length > 0
                ? 'chooseSlug'
                : 'noLoginMethods',
            )}
          </Alert>
        ) : (
          <form
            key={`${state.metadata.scope.slug}:${state.choice}`}
            method={method === 'public-key' || method === 'none' ? 'dialog' : 'post'}
            action={
              method === 'public-key' || method === 'none' ? undefined : '/api/v1/login/password'
            }
            className="login-form"
            onSubmit={(event) => {
              event.preventDefault();
              actions.submit(event.currentTarget);
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
            {option.requestUser && (
              <TextInput
                name="user"
                label={t('user')}
                aria-label={t('user')}
                required
                pattern={'.*\\S.*'}
                maxLength={256}
                value={state.user}
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
                  visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
                  disabled={state.busy}
                />
                <label className="stack" htmlFor="key-certificate">
                  {t(option.certificateRequired ? 'keyCertificateRequired' : 'keyCertificateFile')}
                  <input
                    key={`certificate:${state.inputRevision}`}
                    id="key-certificate"
                    type="file"
                    required={option.certificateRequired}
                    disabled={state.busy}
                  />
                </label>
              </>
            )}
            {state.saved === 'missing' && (
              <Checkbox
                checked={state.optIn}
                onChange={(event) => actions.changeOptIn(event.currentTarget.checked)}
                disabled={state.busy || state.saved !== 'missing'}
                label={t('remember')}
                size="sm"
              />
            )}
            <Group justify="flex-end" gap="xs">
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
