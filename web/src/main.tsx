import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import {
  CssBaseline,
  createTheme,
  GlobalStyles,
  ThemeProvider,
  useMediaQuery,
} from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router/dom';
import './ui/app.css';
import { RememberMeError } from './remember/protocol';
import { App } from './ui/App';
import { reportUiError } from './ui/error-report';
import { type LinkMetadata, loadLinkMetadata } from './ui/link-metadata';
import { t } from './ui/messages';
import { isThemePreference, preferredTheme, saveThemePreference } from './ui/preferences';
import { createSlugRouter, scopeFromSlugLocation } from './ui/slug-router';

const cache = createCache({
  key: 'bifroest',
  nonce: document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? '',
});

function Workspace({ metadata, title }: { metadata: LinkMetadata; title: string }) {
  const [scheme, setScheme] = useState(preferredTheme);
  const dark = useMediaQuery('(prefers-color-scheme: dark)');
  const mode = scheme === 'auto' ? (dark ? 'dark' : 'light') : scheme === 'dark' ? 'dark' : 'light';
  const theme = useMemo(
    () =>
      createTheme({
        palette: { mode },
        typography: {
          fontFamily: 'Roboto, system-ui, sans-serif',
          fontSize: 14,
          button: { textTransform: 'none' },
        },
        components: {
          MuiTooltip: {
            styleOverrides: {
              // The exit-transition portal otherwise retains stale desktop
              // coordinates and can enlarge a resized mobile document while
              // its tooltip is already closed/invisible.
              popperClose: { display: 'none' },
            },
          },
          MuiButton: { defaultProps: { disableElevation: true, size: 'small' } },
          MuiTab: { styleOverrides: { root: { textTransform: 'none', minHeight: 48 } } },
          MuiDialogTitle: { styleOverrides: { root: { fontSize: '1.125rem' } } },
        },
      }),
    [mode],
  );
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
    const scope = scopeFromSlugLocation(location.origin, location);
    if (scope === null) {
      throw new RememberMeError('unavailable');
    }
    const metadata = await loadLinkMetadata(scope);
    const customization = { version: 1, title: t('brand') };
    window.dispatchEvent(new CustomEvent('bifroest:configure', { detail: customization }));
    const title =
      typeof customization.title === 'string' && customization.title.length <= 128
        ? customization.title
        : t('brand');
    document.title = title;
    const router = createSlugRouter(<Workspace metadata={metadata} title={title} />);
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
if (document.readyState === 'complete') {
  void start();
} else {
  document.addEventListener(
    'DOMContentLoaded',
    () => {
      void start();
    },
    { once: true },
  );
}
