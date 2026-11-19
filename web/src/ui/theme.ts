import { createTheme, type PaletteMode } from '@mui/material/styles';

// Shared by both browser entry points; no workspace/terminal dependencies.
export function bifroestTheme(mode: PaletteMode) {
    return createTheme({
        palette: { mode },
        typography: {
            fontFamily: 'Roboto, system-ui, sans-serif',
            fontSize: 14,
            button: { textTransform: 'none' },
        },
        components: {
            MuiTooltip: { styleOverrides: { popperClose: { display: 'none' } } },
            MuiButton: { defaultProps: { disableElevation: true, size: 'small' } },
            MuiTab: { styleOverrides: { root: { textTransform: 'none', minHeight: 48 } } },
            MuiDialogTitle: { styleOverrides: { root: { fontSize: '1.125rem' } } },
        },
    });
}
