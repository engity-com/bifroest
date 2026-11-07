import { Button, Select, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import { m } from './messages';
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
}: {
  disabled: boolean;
  onOpen: (flow: string, id: string) => void;
  onPrepare: (action: 'disconnect' | 'dispose', flow: string, id: string) => void;
  value: SessionTargetValue;
  onChange: (value: SessionTargetValue) => void;
}) {
  const { flow, id, action } = value;
  return (
    <form
      className="stack"
      method="dialog"
      onSubmit={(event) => {
        event.preventDefault();
        if (action === 'details') {
          onOpen(flow, id);
        } else {
          onPrepare(action, flow, id);
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
          maxLength={36}
          pattern="[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"
          disabled={disabled}
        />
      </div>
      <div className="actions">
        <Select
          label={t('managementActionKind')}
          value={action}
          data={[
            { value: 'details', label: t('adminGridOpen') },
            { value: 'disconnect', label: m('disconnect') },
            { value: 'dispose', label: m('end') },
          ]}
          onChange={(value) =>
            onChange({
              flow,
              id,
              action: value === 'disconnect' || value === 'dispose' ? value : 'details',
            })
          }
          disabled={disabled}
        />
        <Button type="submit" disabled={disabled}>
          Go
        </Button>
      </div>
    </form>
  );
}
