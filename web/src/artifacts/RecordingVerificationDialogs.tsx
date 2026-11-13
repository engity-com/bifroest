import type { ComponentProps } from 'react';
import { Modal } from '../ui/material';
import { t } from '../ui/messages';
import type { SourceVerificationResult } from './recording-source-verification';
import { VerificationDialog } from './VerificationDialog';
import { LocalKeyFields, VerificationFields } from './VerificationFields';

export interface RecordingVerificationDialogsProps {
    readonly options: Omit<ComponentProps<typeof VerificationDialog>, 'children'>;
    readonly fields: Omit<ComponentProps<typeof VerificationFields>, 'children'>;
    readonly keyFields: ComponentProps<typeof LocalKeyFields>;
    readonly details: {
        readonly open: boolean;
        close(): void;
        readonly source: string;
        readonly failed: string;
        readonly result: SourceVerificationResult | null;
        readonly used: { producer: string; reported: boolean } | null;
    };
}
export function RecordingVerificationDialogs({
    options,
    fields,
    keyFields,
    details,
}: RecordingVerificationDialogsProps) {
    const { source, failed, result, used } = details;
    return (
        <>
            <VerificationDialog {...options}>
                <VerificationFields {...fields}>
                    <LocalKeyFields {...keyFields} />
                </VerificationFields>
            </VerificationDialog>
            <Modal
                opened={details.open}
                onClose={details.close}
                title={t('recordingVerificationDetails')}
            >
                <dl className="metadata-grid">
                    <dt>{t('verifyAllSource')}</dt>
                    <dd>{source}</dd>
                    <dt>{t('auditEventOutcome')}</dt>
                    <dd>{t(failed ? 'artifactVerificationError' : 'verificationCompleted')}</dd>
                    <dt>{t('artifactDiagnosticCode')}</dt>
                    <dd>{failed || (result?.metadataLimited ? 'metadata-limit' : '—')}</dd>
                    {result?.metadataLimited && (
                        <>
                            <dt>{t('detailsTitle')}</dt>
                            <dd>{t('recordingMetadataIndexLimit')}</dd>
                        </>
                    )}
                    <dt>{t('verificationCheckedRecordings')}</dt>
                    <dd>{result?.checked ?? '—'}</dd>
                    <dt>{t('verifyAllFull')}</dt>
                    <dd>{result?.full ?? '—'}</dd>
                    <dt>{t('verifyAllOuter')}</dt>
                    <dd>{result?.outer ?? '—'}</dd>
                    <dt>{t('artifactExpectedProducer')}</dt>
                    <dd>{used?.producer || t('artifactSignerNotPinned')}</dd>
                    <dt>{t('artifactTrust')}</dt>
                    <dd>
                        {t(
                            !used?.producer
                                ? 'artifactSignerNotPinned'
                                : used.reported
                                  ? 'artifactServerSigner'
                                  : result
                                    ? 'artifactUserSelectedSigner'
                                    : 'verificationMatchNotEstablished',
                        )}
                    </dd>
                </dl>
            </Modal>
        </>
    );
}
