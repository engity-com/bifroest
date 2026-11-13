import { Alert, Button, Modal, Select } from '../ui/material';
import { t } from '../ui/messages';
import { ArtifactSourceDetails } from './ArtifactSourceDetails';
import { EvidenceDetailsDialog } from './EvidenceDetailsDialog';
import type { EvidenceDialogsView } from './evidence-dialogs-view';
import { VerificationDialog } from './VerificationDialog';
import { LocalKeyFields, VerificationFields } from './VerificationFields';

export function EvidenceDialogs({
    notice,
    locked,
    source,
    decryption,
    verification,
    details,
}: EvidenceDialogsView) {
    return (
        <>
            <Modal
                opened={decryption.open}
                onClose={decryption.close}
                title={t('recordingDecrypt')}
            >
                {notice && <Alert color="red">{t(notice)}</Alert>}
                <LocalKeyFields {...decryption.key} disabled={locked} />
                <Button disabled={locked || !decryption.key.candidate} onClick={decryption.unlock}>
                    {t('artifactUnlock')}
                </Button>
            </Modal>
            <VerificationDialog
                open={verification.open}
                source={verification.source}
                kind={verification.kind}
                disabled={verification.disabled}
                onClose={verification.close}
                onStart={verification.start}
                actions={
                    <>
                        {verification.canForget && (
                            <Button disabled={locked} onClick={verification.forget}>
                                {t('artifactForgetKey')}
                            </Button>
                        )}
                        {verification.export && (
                            <Button
                                variant="default"
                                disabled={locked}
                                onClick={() => {
                                    if (verification.export) {
                                        source.onSave(
                                            verification.export.data,
                                            verification.export.filename,
                                        );
                                    }
                                }}
                            >
                                {t('artifactSaveExport')}
                            </Button>
                        )}
                    </>
                }
            >
                {verification.input !== null && (
                    <Select
                        label={t('verificationInput')}
                        value={verification.input}
                        disabled={locked}
                        data={[
                            { value: 'fresh', label: t('verificationFresh') },
                            { value: 'received', label: t('verificationReceived') },
                        ]}
                        onChange={(value) =>
                            verification.selectInput(value === 'received' ? 'received' : 'fresh')
                        }
                    />
                )}
                {notice && (
                    <Alert color="red" role="status">
                        {t(notice)}
                    </Alert>
                )}
                <VerificationFields {...verification.settings} disabled={locked}>
                    {verification.showKey && (
                        <LocalKeyFields
                            {...verification.key}
                            disabled={locked}
                            cached={verification.cached}
                        />
                    )}
                </VerificationFields>
                {verification.canReplace && (
                    <Button disabled={locked} onClick={verification.replace}>
                        {t('artifactReplaceKey')}
                    </Button>
                )}
            </VerificationDialog>
            <EvidenceDetailsDialog
                open={details.open}
                onClose={details.close}
                disabled={locked}
                retryDisabled={details.retryDisabled}
                state={details.state}
                changeSettings={details.changeSettings}
                retryOpen={details.retryOpen}
            >
                {source.received && (
                    <>
                        <ArtifactSourceDetails
                            received={source.received}
                            summary={source.summary}
                            disabled={locked}
                            page={source.page}
                            onPage={source.onPage}
                            onSave={source.onSave}
                            showFiles={false}
                        />
                        <details>
                            <summary>{t('artifactOriginalsAdvanced')}</summary>
                            <ArtifactSourceDetails
                                received={source.received}
                                disabled={locked}
                                page={source.page}
                                onPage={source.onPage}
                                onSave={source.onSave}
                                showMetadata={false}
                            />
                        </details>
                    </>
                )}
            </EvidenceDetailsDialog>
        </>
    );
}
