import { t } from '../ui/messages';
import { m } from './messages';
import type { SessionItem } from './protocol';

export const sessionTime = (value: string) =>
    new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(
        new Date(value),
    );

export const sessionOwnerLabel = (item: SessionItem) =>
    item.owner === null
        ? t(item.policyLimited ? 'managementWithheldOwner' : 'managementUnknownOwner')
        : `${item.owner.issuer} / ${item.owner.subject}`;

export const sessionField = (item: SessionItem, value: string) =>
    value || m(item.policyLimited ? 'withheld' : 'notReported');
