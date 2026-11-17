import type { ProfileResetResult } from '../application/reset-contracts';
import { keyLoginDiagnostic, publicRememberErrorCode } from '../login/diagnostic';
import type { AccessSnapshot } from '../remember';
import { reportUiError } from './error-report';
import { type Message, t } from './messages';

export interface ApplicationNotice {
    key: Message;
    color: 'red' | 'yellow' | 'green';
    context?: AccessSnapshot;
    reset?: ProfileResetResult;
}

export function errorNotice(error: unknown): ApplicationNotice {
    reportUiError('application', error);
    const code = publicRememberErrorCode(error) ?? 'unavailable';
    const diagnostic = keyLoginDiagnostic(error);
    const key: Message =
        code === 'key-import'
            ? 'keyImportFailed'
            : code === 'login-unknown'
              ? 'loginUnknown'
              : code === 'invalid-step'
                ? 'loginInvalidStep'
                : code === 'busy'
                  ? 'loginBusy'
                  : code === 'outcome-unknown'
                    ? 'unknown'
                    : code === 'already-remembered'
                      ? 'already'
                      : code === 'denied'
                        ? 'denied'
                        : code === 'rate-limited'
                          ? 'limited'
                          : code === 'cancelled'
                            ? 'cancelled'
                            : diagnostic
                              ? 'keyUnavailable'
                              : 'unavailable';
    return { key, color: code === 'denied' || code === 'unavailable' ? 'red' : 'yellow' };
}

export function NoticeBody({ notice }: { notice: ApplicationNotice }) {
    return (
        <>
            {notice.reset ? <p>{t(notice.key)}</p> : t(notice.key)}
            {notice.reset && (
                <dl className="metadata-grid">
                    <dt>{t('resetLocalCleared')}</dt>
                    <dd>{notice.reset.localCleared ? '✓' : '✕'}</dd>
                    <dt>{t('resetViewsClosed')}</dt>
                    <dd>{notice.reset.viewsClosed ? '✓' : '✕'}</dd>
                    <dt>{t('resetRemoteUnconfirmed')}</dt>
                    <dd>{notice.reset.remoteUnconfirmed}</dd>
                </dl>
            )}
        </>
    );
}
