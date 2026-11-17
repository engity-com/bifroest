import { Button } from '../ui/material';
import { t } from '../ui/messages';
import { m } from './messages';
import type { VersionInfo } from './protocol';
import { VersionDetails } from './VersionDetails';

export function VersionPage({
    visible,
    version,
    buildVersion,
    loading,
    failed,
    disabled,
    onRefresh,
}: {
    visible: boolean;
    version: VersionInfo | null;
    buildVersion: VersionInfo | null;
    loading: boolean;
    failed: boolean;
    disabled: boolean;
    onRefresh(): void;
}) {
    const info = buildVersion ?? version;
    return (
        <section hidden={!visible} className="stack">
            <div className="section-heading admin-toolbar">
                <Button variant="default" disabled={disabled} onClick={onRefresh}>
                    {m('versionRefresh')}
                </Button>
            </div>
            {loading && <p role="status">{m('versionLoading')}</p>}
            {version === null && !loading && (
                <p className="empty-state">{m(failed ? 'versionUnavailable' : 'versionPending')}</p>
            )}
            {info !== null && (
                <section aria-label={t('managementVersionTitle')}>
                    <VersionDetails info={info} />
                </section>
            )}
        </section>
    );
}
