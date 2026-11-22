import { uuidInputPattern } from '../shared/uuid';
import { Button, Select, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import { m } from './messages';
import type { ManagementPermission } from './permissions';
export interface SessionTargetValue {
    readonly flow: string;
    readonly id: string;
    readonly action: 'details' | 'disconnect' | 'dispose';
}

export function SessionTarget({
    disabled,
    onOpen,
    onPrepare,
    value,
    onChange,
    can,
}: {
    disabled: boolean;
    can: (permission: ManagementPermission) => boolean;
    onOpen: (flow: string, id: string) => void;
    onPrepare: (action: 'disconnect' | 'dispose', flow: string, id: string) => void;
    value: SessionTargetValue;
    onChange: (value: SessionTargetValue) => void;
}) {
    const { flow, id, action } = value;
    const choices = [
        ...(can('sessions.read') ? [{ value: 'details', label: t('adminGridOpen') }] : []),
        ...(can('sessions.disconnect') ? [{ value: 'disconnect', label: m('disconnect') }] : []),
        ...(can('sessions.dispose') ? [{ value: 'dispose', label: m('end') }] : []),
    ];
    const selected = choices.find((choice) => choice.value === action)?.value ?? choices[0]?.value;
    return (
        <form
            className="stack"
            method="dialog"
            onSubmit={(event) => {
                event.preventDefault();
                if (disabled || !selected) {
                    return;
                }
                if (selected === 'details') {
                    onOpen(flow, id);
                } else {
                    if (selected === 'disconnect' || selected === 'dispose') {
                        onPrepare(selected, flow, id);
                    }
                }
            }}
        >
            <div className="actions">
                <TextInput
                    label={t('managementActionFlow')}
                    value={flow}
                    onChange={(event) => onChange({ ...value, flow: event.currentTarget.value })}
                    required
                    maxLength={255}
                    disabled={disabled}
                />
                <TextInput
                    label={t('managementActionID')}
                    value={id}
                    onChange={(event) => onChange({ ...value, id: event.currentTarget.value })}
                    required
                    maxLength={45}
                    pattern={uuidInputPattern}
                    disabled={disabled}
                />
            </div>
            <div className="actions">
                <Select
                    label={t('managementActionKind')}
                    value={selected ?? ''}
                    data={choices}
                    onChange={(value) =>
                        onChange({
                            flow,
                            id,
                            action:
                                value === 'disconnect' || value === 'dispose' ? value : 'details',
                        })
                    }
                    disabled={disabled}
                />
                <Button type="submit" disabled={disabled || !selected}>
                    Go
                </Button>
            </div>
        </form>
    );
}
