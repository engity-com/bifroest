import { Alert, Anchor, Button, PasswordInput, TextInput } from '@mantine/core';
import { useEffect, useId, useRef } from 'react';
import type { LoginStep } from '../remember';
import { t } from './messages';

export function ProviderInformation({
  step,
  providerLink,
}: {
  step: LoginStep;
  providerLink: string | null;
}) {
  return (
    <>
      <Alert color={step.kind === 'error' ? 'red' : 'blue'}>
        <p className="login-message">{step.message}</p>
      </Alert>
      {providerLink !== null && (
        <Anchor
          href={providerLink}
          target="_blank"
          rel="noopener noreferrer"
          referrerPolicy="no-referrer"
        >
          {t('verificationLink')} ({new URL(providerLink).hostname})
        </Anchor>
      )}
    </>
  );
}

export function LoginChallenge({
  step,
  providerLink,
  onAnswer,
  onCancel,
}: {
  step: LoginStep;
  providerLink: string | null;
  onAnswer: (form: HTMLFormElement) => void;
  onCancel: () => void;
}) {
  const response = useRef<HTMLInputElement | null>(null);
  const promptID = useId();
  useEffect(() => {
    response.current?.focus();
  }, []);
  return (
    <form
      method="post"
      action="/_bifroest/api/v1/login/reply"
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        onAnswer(event.currentTarget);
      }}
    >
      <div id={promptID}>
        <ProviderInformation step={step} providerLink={providerLink} />
      </div>
      {step.kind === 'prompt' &&
        (step.echo ? (
          <TextInput
            ref={response}
            name="answer"
            label={t('loginResponse')}
            aria-describedby={promptID}
            autoComplete="off"
          />
        ) : (
          <PasswordInput
            ref={response}
            name="answer"
            label={t('loginResponse')}
            aria-describedby={promptID}
            autoComplete="off"
            visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
          />
        ))}
      <div className="actions">
        <Button type="submit">{t(step.kind === 'prompt' ? 'loginReply' : 'loginContinue')}</Button>
        <Button type="button" variant="default" onClick={onCancel}>
          {t('cancel')}
        </Button>
      </div>
    </form>
  );
}
