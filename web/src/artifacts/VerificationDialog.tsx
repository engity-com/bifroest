import { Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import { type ReactNode, useId } from 'react';
import { Button } from '../ui/material';
import { t } from '../ui/messages';

export function VerificationDialog({
    open,
    source,
    kind,
    disabled = false,
    onClose,
    onStart,
    children,
    actions,
}: {
    open: boolean;
    source: string;
    kind: 'audit' | 'recordings' | 'recording';
    disabled?: boolean;
    onClose(): void;
    onStart(): void;
    children?: ReactNode;
    actions?: ReactNode;
}) {
    const title = useId();
    return (
        <Dialog
            container={
                document.fullscreenElement instanceof HTMLElement
                    ? document.fullscreenElement
                    : undefined
            }
            open={open}
            onClose={onClose}
            aria-labelledby={title}
            fullWidth
            maxWidth="sm"
            keepMounted
        >
            <DialogTitle id={title}>{t('artifactVerificationOptions')}</DialogTitle>
            <DialogContent className="stack">
                <p>
                    {t('verifyAllSource')}: <strong>{source}</strong>
                </p>
                {kind !== 'recording' && (
                    <p>
                        {t(
                            kind === 'recordings'
                                ? 'verificationLocalCatalog'
                                : 'verificationSelectedSourceOnly',
                        )}
                    </p>
                )}
                {children}
            </DialogContent>
            <DialogActions>
                {actions}
                <Button variant="default" onClick={onClose}>
                    {t('cancel')}
                </Button>
                <Button disabled={disabled} onClick={onStart}>
                    {t('verifyStart')}
                </Button>
            </DialogActions>
        </Dialog>
    );
}
