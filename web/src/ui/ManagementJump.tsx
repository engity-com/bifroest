import FactCheckIcon from '@mui/icons-material/FactCheck';
import PeopleOutlineIcon from '@mui/icons-material/PeopleOutlineOutlined';
import ScreenshotMonitorIcon from '@mui/icons-material/ScreenshotMonitor';
import { Button, IconButton, Link, Tooltip } from '@mui/material';
import type { MouseEvent, ReactNode } from 'react';
import type { Scope } from '../remember/protocol';
import { type ManagementLocation, managementPath } from './management-location';
import { useManagementNavigation } from './management-navigation';
import { type Message, t } from './messages';

export const relationID = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(value) &&
  value !== '00000000-0000-0000-0000-000000000000';
export const relationFlow = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[A-Za-z0-9.-]{1,255}$/u.test(value) &&
  !['.', '..', '-'].includes(value);
export function sessionRelation(
  managementFlow: string,
  flow: unknown,
  id: unknown,
): ManagementLocation | null {
  return relationFlow(flow) && relationID(id)
    ? { managementFlow, page: 'sessions', flow, id }
    : null;
}
export function recordingRelation(
  managementFlow: string,
  auditlog: string,
  id: unknown,
): ManagementLocation | null {
  return relationID(id) &&
    /^[A-Za-z0-9._-]{1,128}$/u.test(auditlog) &&
    !['.', '..'].includes(auditlog)
    ? { managementFlow, page: 'recordings', auditlogHint: auditlog, recordingHint: id }
    : null;
}

export function ManagementJump({
  scope,
  target,
  label,
  compact = false,
  disabled = false,
  children,
}: {
  scope: Scope;
  target: ManagementLocation | null;
  label: Message;
  compact?: boolean;
  disabled?: boolean;
  children?: ReactNode;
}) {
  const navigation = useManagementNavigation();
  if (!target) {
    return children ?? null;
  }
  const href = managementPath(scope, target);
  const click = (event: MouseEvent) => {
    event.stopPropagation();
    if (disabled) {
      event.preventDefault();
      return;
    }
    if (
      navigation &&
      event.button === 0 &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.shiftKey &&
      !event.altKey
    ) {
      event.preventDefault();
      navigation.navigate(target);
    }
  };
  const icon =
    target.page === 'sessions' ? (
      <PeopleOutlineIcon fontSize="small" />
    ) : target.page === 'recordings' ? (
      <ScreenshotMonitorIcon fontSize="small" />
    ) : (
      <FactCheckIcon fontSize="small" />
    );
  if (children !== undefined) {
    return (
      <Link href={href} aria-disabled={disabled} onClick={click}>
        {children}
      </Link>
    );
  }
  return compact ? (
    <Tooltip title={t(label)}>
      <span>
        <IconButton
          component="a"
          href={href}
          size="small"
          disabled={disabled}
          aria-label={`${t(label)} ${target.id ?? target.recordingHint ?? target.sessionId ?? ''}`}
          onClick={click}
        >
          {icon}
        </IconButton>
      </span>
    </Tooltip>
  ) : (
    <Button component="a" href={href} startIcon={icon} disabled={disabled} onClick={click}>
      {t(label)}
    </Button>
  );
}
