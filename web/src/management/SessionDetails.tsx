import type { ReactNode, Ref } from 'react';
import { Button } from '../ui/material';
import { t } from '../ui/messages';
import { m, sessionStateLabel } from './messages';
import type { SessionItem } from './protocol';
import { sessionField, sessionOwnerLabel, sessionTime } from './session-display';

// Read-only projection of one selected record. Mutation preparation stays with
// its owning panel; these controls only emit explicit target-bound intents.
export function SessionDetails({
    item,
    detailed,
    id,
    element,
    actions,
    mutationDisabled,
    onPrepare,
}: {
    item: SessionItem;
    detailed: boolean;
    id: string;
    element: Ref<HTMLElement>;
    actions: ReactNode;
    mutationDisabled: boolean;
    onPrepare(action: 'disconnect' | 'dispose', item: SessionItem): void;
}) {
    return (
        <section
            ref={element}
            id={id}
            tabIndex={-1}
            aria-label={m('detailsTitle')}
            className="stack session-details record-card"
        >
            <dl className="metadata-grid">
                {detailed && (
                    <>
                        <dt>{m('user')}</dt>
                        <dd>{sessionField(item, item.user)}</dd>
                    </>
                )}
                <dt>{t('managementFlow')}</dt>
                <dd>{item.flow}</dd>
                <dt>{m('status')}</dt>
                <dd>{sessionStateLabel(item.state)}</dd>
                <dt>{m('started')}</dt>
                <dd>{sessionTime(item.createdAt)}</dd>
                {detailed && (
                    <>
                        <dt>{m('origin')}</dt>
                        <dd>{sessionField(item, item.remote)}</dd>
                    </>
                )}
                <dt>{t('managementSessionId')}</dt>
                <dd className="identifier">{item.id}</dd>
                {detailed &&
                    (item.owner === null ? (
                        <>
                            <dt>{t('managementOwner')}</dt>
                            <dd>{sessionOwnerLabel(item)}</dd>
                        </>
                    ) : (
                        <>
                            <dt>{m('issuer')}</dt>
                            <dd>{item.owner.issuer}</dd>
                            <dt>{m('subject')}</dt>
                            <dd>{item.owner.subject}</dd>
                        </>
                    ))}
                {detailed && item.lastAccessed !== undefined && (
                    <>
                        <dt>{m('lastAccessed')}</dt>
                        <dd>{sessionTime(item.lastAccessed)}</dd>
                    </>
                )}
                <dt>{t('managementValidUntil')}</dt>
                <dd>
                    {item.validUntil === undefined
                        ? t(item.policyLimited ? 'managementWithheldOwner' : 'managementNoLimit')
                        : sessionTime(item.validUntil)}
                </dd>
                <dt>{t('adminGridActions')}</dt>
                <dd className="actions">
                    {actions}
                    <Button
                        disabled={mutationDisabled}
                        color="orange"
                        onClick={() => onPrepare('disconnect', item)}
                    >
                        {m('disconnect')}
                    </Button>
                    <Button
                        disabled={mutationDisabled}
                        color="red"
                        onClick={() => onPrepare('dispose', item)}
                    >
                        {m('end')}
                    </Button>
                </dd>
            </dl>
        </section>
    );
}
