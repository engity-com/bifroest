import type { Ref } from 'react';
import type { ReadProgress } from '../management/progress';
import type { WebAccess } from '../remember';

export type ArtifactPhase = 'downloading' | 'inspecting' | 'verifying' | 'preparing';

export interface ArtifactPanelProps {
  access: WebAccess;
  disabled: boolean;
  remoteDisabled?: boolean;
  active?: boolean;
  view?: 'recordings' | 'auditlogs';
}

export interface ArtifactEvidencePanelProps extends ArtifactPanelProps {
  backgroundAllowed?: boolean;
  verificationCancel?: number;
  onPhaseChange?: (phase: ArtifactPhase | null) => void;
  regionLabel?: string;
  hideBreadcrumbs?: boolean;
  controlRef?: Ref<ArtifactEvidenceControl>;
  onEvidenceState?: (state: ArtifactEvidenceState) => void;
  onResultReady?: () => void;
}

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
