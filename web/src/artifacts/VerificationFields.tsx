import type { ReactNode, RefObject } from 'react';
import { Checkbox, PasswordInput, Select, TextInput } from '../ui/material';
import { t } from '../ui/messages';

// One set of actual local options for recording sets, individual recordings and
// audit snapshots. Only the journal-specific scope is conditional.
export function VerificationFields({
    level,
    onLevel,
    checked,
    onChecked,
    producer,
    onProducer,
    reported,
    disabled,
    auditScope,
    onAuditScope,
    children,
}: {
    level: 'outer' | 'private';
    onLevel(value: 'outer' | 'private'): void;
    checked: boolean;
    onChecked(value: boolean): void;
    producer: string;
    onProducer(value: string): void;
    reported: boolean;
    disabled: boolean;
    auditScope?: 'complete' | 'captured-prefix';
    onAuditScope?(value: 'complete' | 'captured-prefix'): void;
    children?: ReactNode;
}) {
    return (
        <>
            <Select
                label={t('artifactLevel')}
                value={level}
                disabled={disabled}
                data={[
                    { value: 'private', label: t('artifactPrivate') },
                    { value: 'outer', label: t('artifactOuter') },
                ]}
                onChange={(value) => onLevel(value === 'outer' ? 'outer' : 'private')}
            />
            {auditScope && (
                <Select
                    label={t('artifactAuditScope')}
                    value={auditScope}
                    disabled={disabled}
                    data={[
                        { value: 'complete', label: t('artifactComplete') },
                        { value: 'captured-prefix', label: t('artifactPrefix') },
                    ]}
                    onChange={(value) =>
                        onAuditScope?.(value === 'captured-prefix' ? 'captured-prefix' : 'complete')
                    }
                />
            )}
            <Checkbox
                label={t('artifactCheckSigner')}
                checked={checked}
                disabled={disabled}
                onChange={(event) => onChecked(event.currentTarget.checked)}
            />
            <TextInput
                label={t('artifactExpectedProducer')}
                value={producer}
                disabled={disabled || !checked}
                maxLength={64}
                onChange={(event) => onProducer(event.currentTarget.value)}
            />
            {reported && producer && <p className="caption subtle">{t('artifactServerSigner')}</p>}
            {level === 'private' && children}
        </>
    );
}

export function LocalKeyFields({
    input,
    form,
    id,
    passwordID,
    revision,
    candidate,
    onCandidate,
    disabled,
    cached = false,
}: {
    input: RefObject<HTMLInputElement | null>;
    form: RefObject<HTMLFormElement | null>;
    id: string;
    passwordID: string;
    revision: number;
    candidate: boolean;
    onCandidate(value: boolean): void;
    disabled: boolean;
    cached?: boolean;
}) {
    return (
        <form
            ref={form}
            method="dialog"
            className="stack artifact-key"
            onSubmit={(event) => event.preventDefault()}
        >
            <p>{t(cached && !candidate ? 'artifactUsingCachedKey' : 'artifactKeyLocal')}</p>
            <label htmlFor={id}>{t('artifactKeyFile')}</label>
            <input
                key={revision}
                ref={input}
                id={id}
                name="evidence-private"
                type="file"
                disabled={disabled}
                onChange={(event) => {
                    onCandidate((event.currentTarget.files?.length ?? 0) > 0);
                    const password = form.current?.querySelector<HTMLInputElement>(
                        '[name="evidence-passphrase"]',
                    );
                    if (password) {
                        password.value = '';
                    }
                }}
            />
            {candidate && (
                <PasswordInput
                    id={passwordID}
                    name="evidence-passphrase"
                    label={t('artifactPassphrase')}
                    autoComplete="off"
                    disabled={disabled}
                />
            )}
        </form>
    );
}
