import { uuidInputPattern } from '../shared/uuid';
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
  fixedSource = false,
}: {
  view: 'recordings' | 'auditlogs';
  auditlog: string;
  id: string;
  disabled: boolean;
  onAuditlog: (value: string) => void;
  onID: (value: string) => void;
  onGo: () => void;
  fixedSource?: boolean;
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
      {!fixedSource && (
        <TextInput
          label={t('artifactAuditlog')}
          value={auditlog}
          onChange={(event) => onAuditlog(event.currentTarget.value)}
          required
          maxLength={128}
          disabled={disabled}
        />
      )}
      {
        <TextInput
          label={t(view === 'recordings' ? 'artifactRecordingID' : 'artifactEventID')}
          value={id}
          onChange={(event) => onID(event.currentTarget.value)}
          required={view === 'recordings'}
          maxLength={45}
          pattern={uuidInputPattern}
          disabled={disabled}
        />
      }
      <Button type="submit" disabled={disabled}>
        Go
      </Button>
    </form>
  );
}
