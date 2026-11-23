import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { CssBaseline, GlobalStyles, ThemeProvider, useMediaQuery } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router/dom';
import { OidcApplication } from './login/OidcLogin';
import { internalPath } from './shared/upstream';
import { bifroestTheme } from './ui/theme';
import './ui/app.css';
import { App } from './ui/App';
import { afterDocumentReady, configureBrowserTitle } from './ui/customization';
import { reportUiError } from './ui/error-report';
import { type DiscoveryFailure, type LinkMetadata, loadWorkspaceEntry } from './ui/link-metadata';
import { t } from './ui/messages';
import {
    isThemePreference,
    preferredTheme,
    saveThemePreference,
    themePreferenceKey,
} from './ui/preferences';
import { profilePreferencesResetEvent } from './ui/profile-reset';
import { createSlugRouter } from './ui/slug-router';

const cache = createCache({
    key: 'bifroest',
    nonce: document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? '',
});

function Workspace({
    metadata,
    title,
    failure,
}: {
    metadata: LinkMetadata;
    title: string;
    failure?: DiscoveryFailure | undefined;
}) {
    const [scheme, setScheme] = useState(preferredTheme);
    useEffect(() => {
        const reset = () => setScheme(preferredTheme());
        window.addEventListener(profilePreferencesResetEvent, reset);
        return () => window.removeEventListener(profilePreferencesResetEvent, reset);
    }, []);
    useEffect(() => {
        const changed = (event: StorageEvent) => {
            if (event.key === null || event.key === themePreferenceKey) {
                setScheme(preferredTheme());
            }
        };
        window.addEventListener('storage', changed);
        return () => window.removeEventListener('storage', changed);
    }, []);
    const dark = useMediaQuery('(prefers-color-scheme: dark)');
    const mode =
        scheme === 'auto' ? (dark ? 'dark' : 'light') : scheme === 'dark' ? 'dark' : 'light';
    const theme = useMemo(() => bifroestTheme(mode), [mode]);
    useEffect(() => {
        document.documentElement.dataset.colorScheme = mode;
    }, [mode]);
    useEffect(() => {
        window.dispatchEvent(new CustomEvent('bifroest:ready', { detail: { version: 1 } }));
    }, []);
    return (
        <CacheProvider value={cache}>
            <ThemeProvider theme={theme}>
                <CssBaseline enableColorScheme />
                <GlobalStyles
                    styles={{
                        ':root': {
                            '--app-border': theme.palette.divider,
                            '--app-hover': theme.palette.action.hover,
                            '--app-paper': theme.palette.background.paper,
                            '--app-body': theme.palette.background.default,
                            '--app-text': theme.palette.text.primary,
                            '--app-muted': theme.palette.text.secondary,
                            '--app-primary': theme.palette.primary.main,
                            '--app-success': theme.palette.success.main,
                            '--app-warning': theme.palette.warning.main,
                            '--app-error': theme.palette.error.main,
                        },
                    }}
                />
                <App
                    metadata={metadata}
                    initialDiscoveryFailure={failure}
                    title={title}
                    scheme={scheme}
                    onScheme={(next) => {
                        if (isThemePreference(next)) {
                            setScheme(next);
                            saveThemePreference(next);
                        }
                    }}
                />
            </ThemeProvider>
        </CacheProvider>
    );
}

let starting = false;
let started = false;

async function start() {
    if (starting || started) {
        return;
    }
    const container = document.getElementById('root');
    if (container === null) {
        return;
    }
    starting = true;
    try {
        const pathname = internalPath(location.pathname);
        if (pathname === '/login' || pathname.startsWith('/login/')) {
            createRoot(container).render(<OidcApplication title={configureBrowserTitle()} />);
            started = true;
            return;
        }
        const { metadata, failure } = await loadWorkspaceEntry(location.origin, location);
        const title = configureBrowserTitle();
        const router = createSlugRouter(
            <Workspace metadata={metadata} title={title} failure={failure} />,
        );
        createRoot(container).render(<RouterProvider router={router} />);
        started = true;
    } catch (error) {
        reportUiError('bootstrap', error);
        const message = document.createElement('p');
        message.textContent = t('loadFailed');
        const retry = document.createElement('button');
        retry.type = 'button';
        retry.textContent = t('retrySlug');
        retry.addEventListener('click', () => {
            retry.disabled = true;
            void start();
        });
        container.replaceChildren(message, retry);
    } finally {
        starting = false;
    }
}

// Deferred classic customization files must finish before this init event. A
// module running while readyState=interactive must still wait for DOMContentLoaded.
afterDocumentReady(() => {
    void start();
});
