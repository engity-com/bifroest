import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { Box, Button, CircularProgress, IconButton, Stack, Typography } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { t } from '../ui/messages';
import { copyDeviceCode, openDeviceLogin } from './device';
import type { LoginStep } from './interactive';

// This is Bifröst's typed DeviceAuth step, never arbitrary PAM/provider prose.
// Update this small view in place: no terminal transcript or duplicate messages.
export function DeviceLogin({
    device,
    ready,
    onContinue,
    onCancel,
}: {
    device: NonNullable<LoginStep['device']>;
    ready: boolean;
    onContinue(): void;
    onCancel(): void;
}) {
    const [copyResult, setCopyResult] = useState<{ code: string; success: boolean } | null>(null);
    const copied = copyResult?.code === device.userCode ? copyResult.success : null;
    const [blocked, setBlocked] = useState(false);
    const initialCopy = useRef<{ code: string; result: Promise<boolean> } | null>(null);
    const owner = useRef(0);
    useEffect(() => {
        let active = true;
        if (initialCopy.current?.code !== device.userCode) {
            initialCopy.current = {
                code: device.userCode,
                result: copyDeviceCode(device.userCode),
            };
        }
        const generation = owner.current;
        void initialCopy.current.result.then((success) => {
            if (active && owner.current === generation) {
                setCopyResult({ code: device.userCode, success });
            }
        });
        return () => {
            active = false;
            owner.current++;
        };
    }, [device.userCode]);
    return (
        <Stack
            className="bifroest-device-login"
            spacing={2}
            role="group"
            aria-label={t('deviceSignIn')}
        >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography role="status" sx={{ flex: 1, minWidth: 0 }}>
                    {t(copied ? 'deviceCopiedPrefix' : 'deviceManualPrefix')}{' '}
                    <Box component="code" sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
                        {device.userCode}
                    </Box>
                    {t(copied ? 'deviceCopiedSuffix' : 'deviceManualSuffix')}
                </Typography>
                <IconButton
                    size="small"
                    aria-label={t('deviceCopy')}
                    onClick={() => {
                        const generation = ++owner.current;
                        void copyDeviceCode(device.userCode).then((success) => {
                            if (owner.current === generation) {
                                setCopyResult({ code: device.userCode, success });
                            }
                        });
                    }}
                >
                    <ContentCopyIcon fontSize="small" />
                </IconButton>
            </Box>
            {!ready && (
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                    <CircularProgress size={16} />
                    <Typography variant="body2">{t('authenticationWaiting')}</Typography>
                </Stack>
            )}
            {blocked && (
                <Typography role="status" variant="body2">
                    {t('devicePopupBlocked')}
                </Typography>
            )}
            <Stack
                direction={{ xs: 'column-reverse', sm: 'row' }}
                spacing={1}
                sx={{ justifyContent: 'flex-end' }}
            >
                <Button color="inherit" onClick={onCancel}>
                    {t('cancel')}
                </Button>
                <Button
                    component="a"
                    href={device.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    referrerPolicy="no-referrer"
                    variant="contained"
                    autoFocus
                    startIcon={<OpenInNewIcon />}
                    onClick={(event) => {
                        event.preventDefault();
                        setBlocked(!openDeviceLogin(device.url));
                        if (ready) {
                            onContinue();
                        }
                    }}
                >
                    {t('deviceOpen')}
                </Button>
            </Stack>
        </Stack>
    );
}
