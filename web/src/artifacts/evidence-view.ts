import type { Ref } from 'react';
import type { ReadProgress } from '../management/progress';
import type { WebAccess } from '../remember';

import type { ArtifactPhase } from './evidence-job';

export type { ArtifactPhase } from './evidence-job';

export interface ArtifactPanelProps {
    access: WebAccess;
    disabled: boolean;
    remoteDisabled?: boolean;
    active?: boolean;
    view?: 'recordings' | 'auditlogs';
}

interface EvidencePanelControls extends Omit<ArtifactPanelProps, 'view'> {
    backgroundAllowed?: boolean;
    verificationCancel?: number;
    onPhaseChange?: (phase: ArtifactPhase | null) => void;
    regionLabel?: string;
    hideBreadcrumbs?: boolean;
    controlRef?: Ref<ArtifactEvidenceControl>;
    onEvidenceState?: (state: ArtifactEvidenceState) => void;
    onResultReady?: () => void;
}

// A ref exposes commands; it must never implicitly select a different workflow.
export type ArtifactEvidencePanelProps = EvidencePanelControls &
    (
        | { mode?: 'standalone'; view?: 'recordings' | 'auditlogs' }
        | { mode: 'audit-verification'; view: 'auditlogs' }
    );

export interface ArtifactEvidenceControl {
    openOptions(privateFields?: boolean): void;
    cancel(): void;
    showDetails(): void;
}

export interface ArtifactEvidenceState {
    phase: ArtifactPhase | null;
    progress: ReadProgress | null;
    hasGrid: boolean;
    received: boolean;
    status: string | undefined;
    result?: 'success' | 'failure' | undefined;
}
