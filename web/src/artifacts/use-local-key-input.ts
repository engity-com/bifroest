import { useCallback, useId, useRef, useState } from 'react';
import type { LocalKeyInput, LocalKeySelection } from './local-key-input-view';

// One form owns its DOM refs and clearing revision. Sibling exit-transition
// portals cannot clear or rebind another form's file/passphrase input.
export function useLocalKeyInput(): LocalKeyInput {
    const input = useRef<HTMLInputElement | null>(null);
    const form = useRef<HTMLFormElement | null>(null);
    const id = useId();
    const passwordID = useId();
    const [candidate, onCandidate] = useState(false);
    const [revision, setRevision] = useState(0);
    const read = useCallback(
        (): LocalKeySelection => ({
            file: input.current?.files?.[0],
            passphrase:
                form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')
                    ?.value ?? '',
        }),
        [],
    );
    const clear = useCallback(() => {
        if (input.current) {
            input.current.value = '';
        }
        const password = form.current?.querySelector<HTMLInputElement>(
            '[name="evidence-passphrase"]',
        );
        if (password) {
            password.value = '';
        }
        onCandidate(false);
        setRevision((value) => value + 1);
    }, []);
    const clearCandidate = useCallback(() => onCandidate(false), []);
    return {
        fields: { input, form, id, passwordID, revision, candidate, onCandidate },
        read,
        clear,
        clearCandidate,
    };
}
