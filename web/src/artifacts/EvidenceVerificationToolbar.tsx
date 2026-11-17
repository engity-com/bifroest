import CancelIcon from '@mui/icons-material/Cancel';
import { IconButton, Tooltip } from '@mui/material';
import { VerificationResultButton } from '../ui/GridWork';
import { LicenseIcon } from '../ui/LicenseIcon';
import { t } from '../ui/messages';

export function EvidenceVerificationToolbar({
    result,
    busy,
    disabled,
    verifyDisabled,
    showVerify,
    onDetails,
    onVerify,
    onCancel,
}: {
    result: 'success' | 'failure' | null;
    busy: boolean;
    disabled: boolean;
    verifyDisabled: boolean;
    showVerify: boolean;
    onDetails(): void;
    onVerify(): void;
    onCancel(): void;
}) {
    return (
        <>
            {result && (
                <VerificationResultButton result={result} disabled={disabled} onClick={onDetails} />
            )}
            {showVerify && (
                <Tooltip title={t(busy ? 'artifactCancel' : 'verifyOpen')}>
                    <span>
                        <IconButton
                            color="inherit"
                            aria-label={t(busy ? 'artifactCancel' : 'verifyOpen')}
                            disabled={verifyDisabled}
                            onClick={busy ? onCancel : onVerify}
                        >
                            {busy ? <CancelIcon /> : <LicenseIcon />}
                        </IconButton>
                    </span>
                </Tooltip>
            )}
        </>
    );
}
