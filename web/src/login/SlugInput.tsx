import { Autocomplete, TextField } from '@mui/material';
import { useEffect, useState } from 'react';
import { validateScope } from '../remember/protocol';
import { t } from '../ui/messages';

// Published links are suggestions, never a restriction on direct hidden links.
export function SlugInput({
    slug,
    origin,
    options,
    invalid,
    disabled,
    onCommit,
    onEditing,
}: {
    slug: string | null;
    origin: string | null;
    options: readonly string[];
    invalid: boolean;
    disabled: boolean;
    onCommit(slug: string): void;
    onEditing?(editing: boolean): void;
}) {
    const display = slug === '' ? '/' : (slug ?? '');
    const [input, setInput] = useState(display);
    const [syntaxError, setSyntaxError] = useState(false);
    useEffect(() => {
        setInput(display);
        setSyntaxError(false);
    }, [display]);
    const error = syntaxError || (invalid && input === display);
    function commit(value: string) {
        const selected = value === '/' ? '' : value;
        try {
            validateScope({ origin: origin ?? location.origin, slug: selected });
        } catch {
            setSyntaxError(true);
            return;
        }
        setSyntaxError(false);
        onEditing?.(false);
        onCommit(selected);
    }
    return (
        <Autocomplete
            freeSolo
            fullWidth
            clearOnBlur={false}
            onKeyDown={(event) => {
                // Discovery can mount an autofocus login field synchronously.
                // Enter belongs to this selection, never to the newly focused form.
                if (event.key === 'Enter') {
                    event.preventDefault();
                    event.stopPropagation();
                }
            }}
            disabled={disabled}
            options={options.map((value) => value || '/')}
            value={display || null}
            inputValue={input}
            onInputChange={(_event, value, reason) => {
                setInput(value);
                setSyntaxError(false);
                if (reason === 'input' || reason === 'clear') {
                    onEditing?.(value !== display);
                }
            }}
            onChange={(_event, value) => {
                if (value !== null) {
                    commit(value);
                }
            }}
            renderInput={(params) => (
                <TextField
                    {...params}
                    label={t('connectionLink')}
                    size="small"
                    error={error}
                    helperText={error ? t('invalidSlug') : undefined}
                    slotProps={{
                        ...params.slotProps,
                        htmlInput: {
                            ...params.slotProps.htmlInput,
                            maxLength: 129,
                            spellCheck: false,
                            autoCapitalize: 'none',
                            autoCorrect: 'off',
                        },
                    }}
                />
            )}
        />
    );
}
