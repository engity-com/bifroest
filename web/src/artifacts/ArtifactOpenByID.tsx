import { Button, TextInput } from '../ui/material';
import { t } from '../ui/messages';
export function ArtifactOpenByID({
  view,
  auditlog,
  id,
  disabled,
  onAuditlog,
  onID,
  onGo,
}: {
  view: 'recordings' | 'auditlogs';
  auditlog: string;
  id: string;
  disabled: boolean;
  onAuditlog: (value: string) => void;
  onID: (value: string) => void;
  onGo: () => void;
}) {
  return (
    <form
      method="dialog"
      className="artifact-selection"
      data-kind={view}
      onSubmit={(event) => {
        event.preventDefault();
        onGo();
      }}
    >
      <TextInput
        label={t('artifactAuditlog')}
        value={auditlog}
        onChange={(event) => onAuditlog(event.currentTarget.value)}
        required
        maxLength={128}
        disabled={disabled}
      />
      {view === 'recordings' && (
        <TextInput
          label={t('artifactRecordingID')}
          value={id}
          onChange={(event) => onID(event.currentTarget.value)}
          required
          maxLength={36}
          disabled={disabled}
        />
      )}
      <Button type="submit" disabled={disabled}>
        Go
      </Button>
    </form>
  );
}
