import type { RecordingSummary } from '../management/protocol';
import type { Scope } from '../remember/protocol';
import { ManagementJump, sessionRelation } from '../ui/ManagementJump';
import { useManagementNavigation } from '../ui/management-navigation';
import { Button, Title } from '../ui/material';
import { t } from '../ui/messages';
import type { ReceivedArtifact } from './protocol';
import { isLocalRecordingMetadata } from './recording-index';

export function ArtifactSourceDetails({
    received,
    disabled,
    page,
    onPage,
    onSave,
    summary,
    showFiles = true,
    showMetadata = true,
    scope,
    relation,
}: {
    received: ReceivedArtifact;
    disabled: boolean;
    page: number;
    onPage(page: number): void;
    onSave(data: Blob, filename: string): void;
    summary?: RecordingSummary | null;
    showFiles?: boolean;
    showMetadata?: boolean;
    scope?: Scope;
    relation?: { flow: string; sessionId: string };
}) {
    const navigation = useManagementNavigation();
    const context = relation?.sessionId ? relation : summary;
    const session =
        context && navigation
            ? sessionRelation(navigation.location.managementFlow, context.flow, context.sessionId)
            : null;
    return (
        <section className="stack" aria-label={t('artifactHints')}>
            {showMetadata && (
                <>
                    <Title order={4}>
                        {t(
                            showFiles
                                ? 'artifactHints'
                                : received.request.kind === 'recording'
                                  ? 'detailsTitle'
                                  : 'auditLogDetails',
                        )}
                    </Title>
                    <p className="caption subtle">
                        {t(
                            showFiles
                                ? 'artifactTransportWarning'
                                : isLocalRecordingMetadata(summary)
                                  ? 'recordingLocalMetadata'
                                  : 'recordingServerMetadata',
                        )}
                    </p>
                    <dl className="metadata-grid">
                        <dt>{t('artifactSelected')}</dt>
                        <dd>
                            {received.request.auditlog}
                            {received.request.kind === 'recording'
                                ? ` / ${received.request.id}`
                                : ''}
                        </dd>
                        {summary && (
                            <>
                                <dt>{t('recordingIdentity')}</dt>
                                <dd>{summary.user || t('recordingMetadataUnknown')}</dd>
                                <dt>{t('recordingFilterFlow')}</dt>
                                <dd>{summary.flow || '—'}</dd>
                                <dt>{t('recordingFilterTarget')}</dt>
                                <dd>{summary.target || '—'}</dd>
                                <dt>{t('recordingStarted')}</dt>
                                <dd>
                                    {new Intl.DateTimeFormat(undefined, {
                                        dateStyle: 'medium',
                                        timeStyle: 'short',
                                    }).format(new Date(summary.startedAt))}
                                </dd>
                                <dt>{t('recordingFilterStatus')}</dt>
                                <dd>{summary.status}</dd>
                                <dt>{t('recordingSize')}</dt>
                                <dd>
                                    {new Intl.NumberFormat().format(summary.containerBytes)}{' '}
                                    {t('artifactBytes')}
                                </dd>
                            </>
                        )}
                        {context?.sessionId && (
                            <>
                                <dt>{t('managementSessionId')}</dt>
                                <dd>
                                    {scope && session ? (
                                        <ManagementJump
                                            scope={scope}
                                            target={session}
                                            label="showSession"
                                        >
                                            {context.sessionId}
                                        </ManagementJump>
                                    ) : (
                                        context.sessionId
                                    )}
                                </dd>
                            </>
                        )}
                        <dt>{t('artifactProducerHint')}</dt>
                        <dd>
                            {'ProducerID' in received.metadata
                                ? received.metadata.ProducerID
                                : received.metadata.Producer}
                        </dd>
                        {'Recipient' in received.metadata && (
                            <>
                                <dt>{t('artifactRecipientHint')}</dt>
                                <dd>{received.metadata.Recipient || t('artifactHintNone')}</dd>
                            </>
                        )}
                        {scope && session && (
                            <>
                                <dt>{t('adminGridActions')}</dt>
                                <dd className="actions">
                                    <ManagementJump
                                        scope={scope}
                                        target={session}
                                        label="showSession"
                                    />
                                </dd>
                            </>
                        )}
                    </dl>
                </>
            )}
            {showFiles && (
                <>
                    <ul>
                        {received.files.slice(page * 20, (page + 1) * 20).map((file) => (
                            <li key={file.name}>
                                {file.name} ({new Intl.NumberFormat('en-US').format(file.data.size)}{' '}
                                {t('artifactBytes')}){' '}
                                <Button
                                    variant="subtle"
                                    disabled={disabled}
                                    onClick={() =>
                                        onSave(
                                            file.data,
                                            file.name === 'recording' &&
                                                received.request.kind === 'recording'
                                                ? `recording-${received.request.id}.bin`
                                                : file.name,
                                        )
                                    }
                                >
                                    {t('artifactSaveOriginal')} {file.name}
                                </Button>
                            </li>
                        ))}
                    </ul>
                    <div className="artifact-actions">
                        {page > 0 && (
                            <Button
                                variant="default"
                                disabled={disabled}
                                onClick={() => onPage(page - 1)}
                            >
                                {t('artifactPreviousFiles')}
                            </Button>
                        )}
                        {(page + 1) * 20 < received.files.length && (
                            <Button
                                variant="default"
                                disabled={disabled}
                                onClick={() => onPage(page + 1)}
                            >
                                {t('artifactNextFiles')}
                            </Button>
                        )}
                    </div>
                </>
            )}
        </section>
    );
}
