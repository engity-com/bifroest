import BrightnessAutoIcon from '@mui/icons-material/BrightnessAutoOutlined';
import DarkModeIcon from '@mui/icons-material/DarkModeOutlined';
import LightModeIcon from '@mui/icons-material/LightModeOutlined';
import { ActionIcon, Tooltip } from './material';
import { t } from './messages';

export function ThemeSwitcher({
    scheme,
    onScheme,
}: {
    scheme: string;
    onScheme: (value: string) => void;
}) {
    const modes = ['auto', 'light', 'dark'] as const;
    const current = modes.find((mode) => mode === scheme) ?? 'auto';
    const next = modes[(modes.indexOf(current) + 1) % modes.length] ?? 'auto';
    return (
        <Tooltip label={`${t('theme')}: ${t(current)} → ${t(next)}`}>
            <ActionIcon
                variant="subtle"
                color="gray"
                size="lg"
                aria-label={`${t('theme')}: ${t(current)}`}
                onClick={() => onScheme(next)}
            >
                {current === 'auto' ? (
                    <BrightnessAutoIcon />
                ) : current === 'light' ? (
                    <LightModeIcon />
                ) : (
                    <DarkModeIcon />
                )}
            </ActionIcon>
        </Tooltip>
    );
}
