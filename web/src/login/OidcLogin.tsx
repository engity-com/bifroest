import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import {
    Alert,
    Box,
    Button,
    CircularProgress,
    CssBaseline,
    Paper,
    Stack,
    ThemeProvider,
    Typography,
    useMediaQuery,
} from '@mui/material';
import { useEffect, useMemo, useRef, useState } from 'react';
import logo from '../../../docs/assets/favicon.svg?no-inline';
import { t } from '../ui/messages';
import { bifroestTheme } from '../ui/theme';
import { type OidcView, oidcEntry, oidcFinished, oidcRequest } from './oidc';

// The same flow/view is used by the full application and its small standalone
// entry. No workspace, discovery, terminal, key worker or artifact imports.
export function OidcLogin({ title = t('brand') }: { title?: string }) {
    const dialog = useMediaQuery('(min-width: 600px) and (min-height: 480px)');
    const [route, setRoute] = useState(() => location.href);
    const [view, setView] = useState<OidcView | null>(null);
    const [failed, setFailed] = useState(false);
    const [busy, setBusy] = useState(false);
    const owner = useRef(0);
    const mounted = useRef<AbortController | null>(null);
    const id = view?.id;
    const status = view?.status;
    useEffect(() => {
        const changed = () => setRoute(location.href);
        window.addEventListener('hashchange', changed);
        window.addEventListener('popstate', changed);
        changed();
        return () => {
            window.removeEventListener('hashchange', changed);
            window.removeEventListener('popstate', changed);
        };
    }, []);
    useEffect(() => {
        const controller = new AbortController();
        owner.current++;
        mounted.current = controller;
        const dispose = () => {
            controller.abort();
            if (mounted.current === controller) {
                mounted.current = null;
            }
        };
        const current = new URL(route);
        const entry = oidcEntry(current);
        setView(null);
        setFailed(false);
        setBusy(false);
        if (!entry) {
            if (current.hash !== '#waiting') {
                setFailed(true);
            }
            return dispose;
        }
        void oidcRequest(entry.action, entry.fields, controller.signal)
            .then(async (next) => {
                if (controller.signal.aborted) {
                    return;
                }
                history.replaceState(null, '', `/login/#attempt/${next.id}`);
                setView(next);
                if (next.url) {
                    await new Promise<void>((resolve) =>
                        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
                    );
                    if (!controller.signal.aborted) {
                        location.assign(next.url);
                    }
                }
            })
            .catch(() => {
                if (!controller.signal.aborted) {
                    setFailed(true);
                }
            });
        return dispose;
    }, [route]);
    useEffect(() => {
        if (
            !id ||
            !status ||
            ['accepted', 'denied', 'expired'].includes(status) ||
            failed ||
            busy
        ) {
            return;
        }
        const controller = new AbortController();
        let timer: ReturnType<typeof setTimeout>;
        const poll = async () => {
            const generation = owner.current;
            try {
                const next = await oidcRequest('status', { id }, controller.signal);
                if (!controller.signal.aborted && generation === owner.current) {
                    setView(next);
                }
                if (!oidcFinished(next) && !controller.signal.aborted) {
                    timer = setTimeout(() => {
                        void poll();
                    }, 1000);
                }
            } catch {
                if (!controller.signal.aborted && generation === owner.current) {
                    setFailed(true);
                }
            }
        };
        timer = setTimeout(() => {
            void poll();
        }, 1000);
        return () => {
            controller.abort();
            clearTimeout(timer);
        };
    }, [id, status, failed, busy]);
    useEffect(() => {
        if (view?.status === 'accepted' && !view.ssh) {
            window.close();
        }
    }, [view]);
    const choose = async (code: string | null) => {
        if (!view?.csrf || busy || view.status !== 'approval' || !mounted.current) {
            return;
        }
        // Capture this exact route/decision owner. The mutable ref may already
        // point at another login when a response (or its abort error) arrives.
        const controller = mounted.current;
        const generation = ++owner.current;
        const current = () =>
            mounted.current === controller &&
            !controller.signal.aborted &&
            owner.current === generation;
        setBusy(true);
        try {
            const next = await oidcRequest(
                code === null ? 'deny' : 'approve',
                { id: view.id, csrf: view.csrf, ...(code === null ? {} : { code }) },
                controller.signal,
            );
            if (current()) {
                setView(next);
            }
        } catch {
            if (current()) {
                setFailed(true);
            }
        } finally {
            if (current()) {
                setBusy(false);
            }
        }
    };
    const accepted = view?.status === 'accepted';
    const rejected = failed || view?.status === 'denied' || view?.status === 'expired';
    const approval = view?.status === 'approval';
    return (
        <Box
            component="main"
            className="bifroest-login"
            sx={{
                minHeight: '100dvh',
                display: 'grid',
                placeItems: dialog ? 'center' : 'stretch',
                p: dialog ? 3 : 0,
            }}
        >
            <Stack spacing={dialog ? 2 : 0} sx={{ width: '100%', maxWidth: dialog ? 440 : 'none' }}>
                <Stack
                    className="bifroest-login-brand bifroest-login-brand-outside"
                    direction="row"
                    spacing={1}
                    sx={{
                        display: dialog ? 'flex' : 'none',
                        alignItems: 'center',
                        justifyContent: 'center',
                    }}
                >
                    <Box component="img" src={logo} alt="" sx={{ width: 28, height: 28 }} />
                    <Typography variant="body1" sx={{ fontWeight: 500, overflowWrap: 'anywhere' }}>
                        {title}
                    </Typography>
                </Stack>
                <Paper
                    component="section"
                    className="bifroest-login-card"
                    aria-labelledby="oidc-title"
                    elevation={3}
                    sx={{
                        width: '100%',
                        maxWidth: dialog ? 440 : 'none',
                        minHeight: dialog ? 'auto' : '100dvh',
                        borderRadius: dialog ? 2 : 0,
                        p: dialog ? 4 : 3,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'center',
                    }}
                >
                    <Stack spacing={3}>
                        <Stack
                            className="bifroest-login-brand bifroest-login-brand-inside"
                            direction="row"
                            spacing={1}
                            sx={{ display: dialog ? 'none' : 'flex', alignItems: 'center' }}
                        >
                            <Box component="img" src={logo} alt="" sx={{ width: 22, height: 22 }} />
                            <Typography
                                variant="body2"
                                color="text.secondary"
                                sx={{ overflowWrap: 'anywhere' }}
                            >
                                {title}
                            </Typography>
                        </Stack>
                        <Typography
                            id="oidc-title"
                            className="bifroest-login-title"
                            component="h1"
                            variant="h6"
                        >
                            {t(
                                accepted
                                    ? 'oidcAccepted'
                                    : rejected
                                      ? 'oidcDenied'
                                      : approval
                                        ? 'oidcChoose'
                                        : 'oidcWaiting',
                            )}
                        </Typography>
                        {accepted ? (
                            <Alert severity="success">
                                {t(view.ssh ? 'oidcSSHSuccess' : 'oidcWebSuccess')}
                            </Alert>
                        ) : rejected ? (
                            <Alert severity="error">
                                {t(
                                    view?.error === 'code_mismatch'
                                        ? 'oidcWrongCode'
                                        : view?.error === 'access_denied'
                                          ? 'oidcAccessDenied'
                                          : 'oidcFailed',
                                )}
                            </Alert>
                        ) : approval ? (
                            <>
                                <Typography className="bifroest-login-instructions">
                                    {t('oidcChooseHint')} {t('oidcWrongCodeWarning')}
                                </Typography>
                                <Box
                                    className="bifroest-login-choices"
                                    sx={{
                                        display: 'grid',
                                        gridTemplateColumns: 'repeat(3, 1fr)',
                                        gap: 2,
                                    }}
                                >
                                    {view.choices?.map((code) => (
                                        <Button
                                            key={code}
                                            variant="outlined"
                                            disabled={busy}
                                            aria-label={`${t('oidcCode')} ${code}`}
                                            onClick={() => {
                                                void choose(code);
                                            }}
                                            sx={{
                                                minHeight: 64,
                                                fontFamily: 'monospace',
                                                fontSize: '1.5rem',
                                                letterSpacing: '.15em',
                                            }}
                                        >
                                            {code}
                                        </Button>
                                    ))}
                                </Box>
                                <Button
                                    className="bifroest-login-decline"
                                    variant="outlined"
                                    fullWidth
                                    sx={{ minHeight: 44 }}
                                    color="error"
                                    disabled={busy}
                                    onClick={() => {
                                        void choose(null);
                                    }}
                                >
                                    {t('oidcDecline')}
                                </Button>
                            </>
                        ) : (
                            <Box
                                role="status"
                                aria-live="polite"
                                sx={{ display: 'flex', gap: 2, alignItems: 'center' }}
                            >
                                <CircularProgress size={24} />
                                <Typography>
                                    {t(
                                        view?.status === 'authorizing'
                                            ? 'oidcCheckingAccess'
                                            : 'oidcLoading',
                                    )}
                                </Typography>
                            </Box>
                        )}
                    </Stack>
                </Paper>
            </Stack>
        </Box>
    );
}

export function OidcApplication({ title = t('brand') }: { title?: string }) {
    const dark = useMediaQuery('(prefers-color-scheme: dark)');
    const theme = useMemo(() => bifroestTheme(dark ? 'dark' : 'light'), [dark]);
    const cache = useMemo(
        () =>
            createCache({
                key: 'bifroest',
                nonce:
                    document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')
                        ?.content ?? '',
            }),
        [],
    );
    useEffect(() => {
        document.documentElement.dataset.colorScheme = dark ? 'dark' : 'light';
    }, [dark]);
    useEffect(() => {
        window.dispatchEvent(new CustomEvent('bifroest:ready', { detail: { version: 1 } }));
    }, []);
    return (
        <CacheProvider value={cache}>
            <ThemeProvider theme={theme}>
                <CssBaseline enableColorScheme />
                <OidcLogin title={title} />
            </ThemeProvider>
        </CacheProvider>
    );
}
