import { Alert, Anchor, Button, PasswordInput, TextInput } from '@mantine/core';
import { useEffect, useRef } from 'react';
import type { LoginStep } from '../remember';
import { t } from './messages';

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
      {step.kind === 'prompt' &&
        (step.echo ? (
          <TextInput ref={response} name="answer" label={t('loginResponse')} autoComplete="off" />
        ) : (
          <PasswordInput
            ref={response}
            name="answer"
            label={t('loginResponse')}
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
