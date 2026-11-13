import type { ReactNode } from 'react';
import { Alert, Button, Modal } from '../ui/material';
import { t } from '../ui/messages';
import { type EvidenceDetailsState, evidenceDetails } from './evidence-details';

export function EvidenceDetailsDialog({
    open,
    state,
    disabled,
    changeSettings,
    retryOpen,
    retryDisabled,
    onClose,
    children,
}: {
    open: boolean;
    state: EvidenceDetailsState;
    disabled: boolean;
    changeSettings: (() => void) | null;
    retryOpen: (() => void) | null;
    retryDisabled: boolean;
    onClose(): void;
    children: ReactNode;
}) {
    const details = evidenceDetails(state);
    return (
        <Modal opened={open} onClose={onClose} title={t('recordingVerificationDetails')}>
            <div className="stack">
                {details.message && <Alert color="red">{t(details.message)}</Alert>}
                {changeSettings && (
                    <Button variant="default" disabled={disabled} onClick={changeSettings}>
                        {t('recordingChangeVerification')}
                    </Button>
                )}
                {retryOpen && (
                    <Button disabled={retryDisabled} onClick={retryOpen}>
                        {t('recordingRetryOpen')}
                    </Button>
                )}
                <dl className="metadata-grid">
                    <dt>{t('artifactDiagnosticCode')}</dt>
                    <dd>{details.code}</dd>
                    <dt>{t('artifactDiagnosticStage')}</dt>
                    <dd>{details.stage}</dd>
                    <dt>{t('artifactValidation')}</dt>
                    <dd>{details.validation}</dd>
                    <dt>{t('artifactVerifiedProducer')}</dt>
                    <dd>{details.producer}</dd>
                    <dt>{t('artifactExpectedProducer')}</dt>
                    <dd>{details.expectedProducer ?? t('artifactSignerNotPinned')}</dd>
                    <dt>{t('artifactTrust')}</dt>
                    <dd>{t(details.trust)}</dd>
                    <dt>{t('artifactDerivedRecipient')}</dt>
                    <dd>
                        {details.recipient ??
                            t(
                                details.protectionKnown
                                    ? 'artifactNotEncrypted'
                                    : 'recordingMetadataUnknown',
                            )}
                    </dd>
                    <dt>{t('artifactDecryption')}</dt>
                    <dd>{details.decryption}</dd>
                    {details.audit && (
                        <>
                            <dt>{t('artifactRecordCount')}</dt>
                            <dd>{details.audit.records}</dd>
                            <dt>{t('artifactPrivateCount')}</dt>
                            <dd>{details.audit.privateRecords}</dd>
                            <dt>{t('artifactAuditScope')}</dt>
                            <dd>{details.audit.scope}</dd>
                        </>
                    )}
                </dl>
                {children}
            </div>
        </Modal>
    );
}
