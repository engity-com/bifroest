// Presentation adapters for the existing forms. These render Material UI
// components only; authentication, ownership and transport stay outside them.
import CloseIcon from '@mui/icons-material/Close';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import type { ButtonProps, PaperProps, TextFieldProps, TypographyProps } from '@mui/material';
import {
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  FormHelperText,
  FormLabel,
  IconButton,
  InputAdornment,
  Link,
  MenuItem,
  Alert as MuiAlert,
  Button as MuiButton,
  Checkbox as MuiCheckbox,
  Paper as MuiPaper,
  Radio as MuiRadio,
  Stack as MuiStack,
  Table as MuiTable,
  Tooltip as MuiTooltip,
  RadioGroup,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  useTheme,
} from '@mui/material';
import type { ChangeEvent, ComponentProps, ReactNode, Ref } from 'react';
import { useId, useState } from 'react';

type Color = 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'gray' | undefined;
const colors = {
  red: 'error',
  orange: 'warning',
  yellow: 'warning',
  green: 'success',
  blue: 'primary',
  gray: 'inherit',
} as const;
const space = (value: string | number | undefined) =>
  typeof value === 'number' ? value / 8 : value === 'xs' ? 1 : value === 'lg' ? 2.5 : 1.5;

export function Alert({
  color,
  children,
  ...props
}: Omit<ComponentProps<typeof MuiAlert>, 'color'> & { color?: Color }) {
  return (
    <MuiAlert
      {...props}
      severity={
        color === 'red'
          ? 'error'
          : color === 'yellow' || color === 'orange'
            ? 'warning'
            : color === 'green'
              ? 'success'
              : 'info'
      }
    >
      {children}
    </MuiAlert>
  );
}

export function Button({
  variant,
  color,
  size,
  children,
  ...props
}: Omit<ButtonProps, 'variant' | 'color' | 'size'> & {
  variant?:
    | 'default'
    | 'subtle'
    | 'light'
    | 'outline'
    | 'filled'
    | 'contained'
    | 'text'
    | 'outlined';
  color?: Color;
  size?: 'xs' | 'sm' | 'md' | 'lg';
}) {
  return (
    <MuiButton
      {...props}
      color={color ? colors[color] : 'primary'}
      size={size === 'lg' ? 'large' : size === 'md' ? 'medium' : 'small'}
      variant={
        variant === 'default' || variant === 'outline' || variant === 'outlined'
          ? 'outlined'
          : variant === 'subtle' || variant === 'light' || variant === 'text'
            ? 'text'
            : 'contained'
      }
    >
      {children}
    </MuiButton>
  );
}

type FieldProps = Omit<TextFieldProps, 'ref' | 'size' | 'onChange'> & {
  ref?: Ref<HTMLInputElement>;
  maxLength?: number;
  pattern?: string;
  'data-autofocus'?: boolean;
  onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
};
export function TextInput({
  ref,
  maxLength,
  pattern,
  'aria-label': ariaLabel,
  'data-autofocus': autofocus,
  ...props
}: FieldProps) {
  return (
    <TextField
      {...props}
      fullWidth
      size="small"
      inputRef={ref}
      autoFocus={autofocus ?? props.autoFocus}
      slotProps={{ htmlInput: { maxLength, pattern, 'aria-label': ariaLabel } }}
    />
  );
}
export function PasswordInput({
  ref,
  visibilityToggleButtonProps,
  maxLength,
  pattern,
  'data-autofocus': autofocus,
  ...props
}: FieldProps & { visibilityToggleButtonProps?: { 'aria-label': string } }) {
  const [visible, setVisible] = useState(false);
  return (
    <TextField
      {...props}
      fullWidth
      size="small"
      inputRef={ref}
      autoFocus={autofocus ?? props.autoFocus}
      type={visible ? 'text' : 'password'}
      slotProps={{
        htmlInput: { maxLength, pattern },
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <IconButton
                edge="end"
                size="small"
                aria-label={visibilityToggleButtonProps?.['aria-label']}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => setVisible((value) => !value)}
              >
                {visible ? <VisibilityOffIcon /> : <VisibilityIcon />}
              </IconButton>
            </InputAdornment>
          ),
        },
      }}
    />
  );
}

export function Checkbox({
  label,
  description,
  size: _size,
  ...props
}: Omit<ComponentProps<typeof MuiCheckbox>, 'size'> & {
  label: ReactNode;
  description?: ReactNode;
  size?: 'sm' | 'small';
}) {
  return (
    <div>
      <FormControlLabel label={label} control={<MuiCheckbox {...props} size="small" />} />
      {description && <FormHelperText>{description}</FormHelperText>}
    </div>
  );
}

type Data = readonly (string | { value: string; label: ReactNode; disabled?: boolean })[];
export function Select({
  data,
  value,
  onChange,
  allowDeselect: _allowDeselect,
  ...props
}: Omit<FieldProps, 'value' | 'onChange'> & {
  data: Data;
  value: string | null;
  onChange: (value: string | null) => void;
  allowDeselect?: boolean;
}) {
  return (
    <TextField
      {...props}
      select
      fullWidth
      size="small"
      value={value ?? ''}
      onChange={(event) => onChange(event.target.value)}
    >
      {data.map((entry) =>
        typeof entry === 'string' ? (
          <MenuItem key={entry} value={entry}>
            {entry}
          </MenuItem>
        ) : (
          <MenuItem key={entry.value} value={entry.value} disabled={entry.disabled}>
            {entry.label}
          </MenuItem>
        ),
      )}
    </TextField>
  );
}

export function Title({
  order = 2,
  size: _size,
  children,
  ...props
}: {
  order?: 1 | 2 | 3 | 4 | 5 | 6;
  size?: string;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <Typography
      {...props}
      component={`h${order}` as 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6'}
      variant={order < 3 ? 'h5' : order === 3 ? 'h6' : 'subtitle1'}
    >
      {children}
    </Typography>
  );
}
export function Text({
  size,
  c,
  mb,
  ...props
}: TypographyProps & { size?: 'xs' | 'sm'; c?: string; mb?: string }) {
  return (
    <Typography
      {...props}
      variant={size === 'xs' ? 'caption' : size === 'sm' ? 'body2' : 'body1'}
      color={c === 'dimmed' ? 'text.secondary' : undefined}
      sx={{ mb: mb ? space(mb) : 0 }}
    />
  );
}
export function Paper({
  withBorder,
  p,
  ...props
}: PaperProps & { withBorder?: boolean; p?: string | number }) {
  return (
    <MuiPaper
      {...props}
      variant={withBorder ? 'outlined' : 'elevation'}
      elevation={withBorder ? 0 : 1}
      sx={{ p: p ? space(p) : 0 }}
    />
  );
}
export function Stack({
  gap = 'sm',
  ...props
}: ComponentProps<typeof MuiStack> & { gap?: string | number }) {
  return <MuiStack {...props} spacing={space(gap)} />;
}
export function Group({
  justify,
  gap,
  ...props
}: ComponentProps<typeof MuiStack> & { justify?: string; gap?: string | number }) {
  return (
    <MuiStack
      {...props}
      direction="row"
      useFlexGap
      sx={{ flexWrap: 'wrap', alignItems: 'center', justifyContent: justify }}
      spacing={space(gap)}
    />
  );
}
export function Tooltip({
  label,
  ...props
}: Omit<ComponentProps<typeof MuiTooltip>, 'title'> & { label: ReactNode }) {
  return <MuiTooltip {...props} title={label} />;
}
export const Anchor = Link;
export const VisuallyHidden = (props: ComponentProps<typeof Box>) => (
  <Box
    {...props}
    component="span"
    sx={{
      position: 'absolute',
      width: 1,
      height: 1,
      p: 0,
      m: -1,
      overflow: 'hidden',
      clipPath: 'inset(50%)',
      whiteSpace: 'nowrap',
    }}
  />
);
export { ActionIcon, Menu } from './material-menu';

export function SegmentedControl({
  data,
  value,
  onChange,
  disabled,
  'aria-label': label,
}: {
  data: Data;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  fullWidth?: boolean;
  'aria-label'?: string;
}) {
  return (
    <ToggleButtonGroup
      exclusive
      fullWidth
      size="small"
      value={value}
      disabled={disabled}
      aria-label={label}
      role="radiogroup"
      onKeyDown={(event) => {
        if (
          disabled ||
          !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)
        ) {
          return;
        }
        const entries = data
          .map((entry) => (typeof entry === 'string' ? { value: entry, label: entry } : entry))
          .filter((entry) => !entry.disabled);
        if (!entries.length) {
          return;
        }
        event.preventDefault();
        const index = entries.findIndex((entry) => entry.value === value);
        const next =
          entries[
            event.key === 'Home'
              ? 0
              : event.key === 'End'
                ? entries.length - 1
                : (index +
                    (event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1) +
                    entries.length) %
                  entries.length
          ];
        if (next) {
          onChange(next.value);
          event.currentTarget.querySelector<HTMLElement>(`[value="${next.value}"]`)?.focus();
        }
      }}
      onChange={(_event, next: unknown) => {
        if (typeof next === 'string') {
          onChange(next);
        }
      }}
    >
      {data.map((entry) => {
        const item = typeof entry === 'string' ? { value: entry, label: entry } : entry;
        return (
          <ToggleButton
            key={item.value}
            value={item.value}
            role="radio"
            aria-checked={value === item.value}
            tabIndex={value === item.value ? 0 : -1}
            disabled={disabled || item.disabled}
          >
            {item.label}
          </ToggleButton>
        );
      })}
    </ToggleButtonGroup>
  );
}

function RadioOption({
  label,
  value,
  disabled,
  description,
}: {
  label: ReactNode;
  value: string;
  disabled?: boolean;
  description?: ReactNode;
}) {
  const descriptionId = useId();
  return (
    <div>
      <FormControlLabel
        label={label}
        value={value}
        disabled={disabled}
        control={
          <MuiRadio
            size="small"
            slotProps={{ input: { 'aria-describedby': description ? descriptionId : undefined } }}
          />
        }
      />
      {description && <FormHelperText id={descriptionId}>{description}</FormHelperText>}
    </div>
  );
}
function RadioOptions({
  label,
  value,
  onChange,
  children,
}: {
  label?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <FormControl>
      <FormLabel id={id}>{label}</FormLabel>
      <RadioGroup
        aria-labelledby={label ? id : undefined}
        value={value}
        onChange={(_event, next) => onChange(next)}
      >
        {children}
      </RadioGroup>
    </FormControl>
  );
}
export const Radio = Object.assign(RadioOption, { Group: RadioOptions });

function MaterialTable({
  captionSide,
  sx,
  ...props
}: ComponentProps<typeof MuiTable> & { captionSide?: 'top' | 'bottom' }) {
  return <MuiTable {...props} size="small" sx={{ captionSide, ...sx }} />;
}
export const Table = Object.assign(MaterialTable, {
  Thead: TableHead,
  Tbody: TableBody,
  Tr: TableRow,
  Th: (props: ComponentProps<typeof TableCell>) => (
    <TableCell {...props} component="th" scope="col" />
  ),
  Td: TableCell,
});

export function Modal({
  opened,
  onClose,
  title,
  children,
  classNames,
  closeOnClickOutside = true,
  closeOnEscape = true,
  withCloseButton = true,
  closeButtonProps,
  lockScroll = false,
  size: _size,
  padding: _padding,
  centered: _centered,
}: {
  opened: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  classNames?: { content: string };
  closeOnClickOutside?: boolean;
  closeOnEscape?: boolean;
  withCloseButton?: boolean;
  closeButtonProps?: { 'aria-label': string };
  lockScroll?: boolean;
  size?: string;
  padding?: string;
  centered?: boolean;
}) {
  const id = useId();
  return (
    <Dialog
      open={opened}
      fullWidth
      maxWidth="xs"
      aria-labelledby={id}
      disableScrollLock={!lockScroll}
      onClose={(_event, reason) => {
        if (
          (reason === 'backdropClick' && closeOnClickOutside) ||
          (reason === 'escapeKeyDown' && closeOnEscape)
        ) {
          onClose();
        }
      }}
      slotProps={{ paper: { className: classNames?.content } }}
    >
      <DialogTitle
        id={`${id}-heading`}
        sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2 }}
      >
        <span id={id}>{title}</span>
        {withCloseButton && (
          <IconButton
            size="small"
            aria-label={closeButtonProps?.['aria-label'] ?? 'Close'}
            onClick={onClose}
          >
            <CloseIcon fontSize="small" />
          </IconButton>
        )}
      </DialogTitle>
      <DialogContent sx={{ pt: '8px !important' }}>{children}</DialogContent>
    </Dialog>
  );
}

export function useComputedColorScheme(_fallback?: string) {
  return useTheme().palette.mode;
}
