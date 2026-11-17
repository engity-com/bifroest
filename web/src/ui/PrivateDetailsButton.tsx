import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import { IconButton, Tooltip } from '@mui/material';
import { t } from './messages';
export function PrivateDetailsButton({
    checked,
    disabled,
    onChange,
}: {
    checked: boolean;
    disabled: boolean;
    onChange(): void;
}) {
    return (
        <Tooltip title={t(checked ? 'adminGridHideDetails' : 'adminGridShowDetails')}>
            <span>
                <IconButton
                    aria-label={t(checked ? 'adminGridHideDetails' : 'adminGridShowDetails')}
                    aria-pressed={checked}
                    disabled={disabled}
                    onClick={onChange}
                >
                    {checked ? <VisibilityOffIcon /> : <VisibilityIcon />}
                </IconButton>
            </span>
        </Tooltip>
    );
}
