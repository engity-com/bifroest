import type { ReactNode } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { RecordingSummary } from '../management/protocol';
import type { Scope } from '../remember/protocol';
import { Button, useComputedColorScheme } from '../ui/material';
import { type Message, t } from '../ui/messages';
import { ReadProgress } from '../ui/ReadProgress';
import { ArtifactSourceDetails } from './ArtifactSourceDetails';
import type { ArtifactPhase } from './evidence-job';
import type { RecordingInfo } from './open-recording';
import type { PreparedPlayback } from './prepared-playback';
import type { ReceivedArtifact } from './protocol';
import { RecordingPlayer } from './RecordingPlayer';

// Recording presentation receives local document data and explicit user commands,
// never a WebAccess, worker factory, key cache or mutable workflow controller.
export function RecordingEvidenceView({
    received,
    summary,
    info,
    playback,
    phase,
    progress,
    notice,
    disabled,
    locked,
    active,
    showPlaceholder,
    playbackAllowed,
    verificationControls,
    scope,
    relation,
    page,
    onPage,
    onSave,
    onOpen,
    onOperationDetails,
}: {
    received: ReceivedArtifact | null;
    summary: RecordingSummary | null;
    info: RecordingInfo | null;
    playback: { readonly source: Blob; readonly image: PreparedPlayback } | null;
    phase: ArtifactPhase | null;
    progress: Progress | null;
    notice: Message | null;
    disabled: boolean;
    locked: boolean;
    active: boolean;
    showPlaceholder: boolean;
    playbackAllowed: boolean;
    verificationControls: ReactNode;
    scope: Scope;
    relation: { readonly flow: string; readonly sessionId: string };
    page: number;
    onPage(value: number): void;
    onSave(data: Blob, filename: string): void;
    onOpen(): void;
    onOperationDetails(): void;
}) {
    const palette = useComputedColorScheme('light');
    return (
        <>
            {showPlaceholder && (playback === null || phase !== null) && (
                <section
                    className={`recording-video${palette === 'dark' ? ' recording-video--dark' : ''}`}
                    aria-label={t('playbackVideo')}
                    aria-busy={phase !== null}
                >
                    <div className="recording-overlay">
                        {phase ? (
                            <div className="stack recording-loading">
                                <span>
                                    {t(
                                        phase === 'downloading'
                                            ? 'recordingOpening'
                                            : phase === 'preparing'
                                              ? 'playbackPreparing'
                                              : phase === 'inspecting'
                                                ? 'artifactInspecting'
                                                : 'recordingVerifying',
                                    )}
                                </span>
                                <ReadProgress value={progress} />
                            </div>
                        ) : (
                            <div className="stack">
                                {notice && <span>{t(notice)}</span>}
                                <Button disabled={locked || !received} onClick={onOpen}>
                                    {t(info?.requiresKey ? 'artifactUnlock' : 'recordingOpen')}
                                </Button>
                                {notice && (
                                    <Button variant="subtle" onClick={onOperationDetails}>
                                        {t('detailsTitle')}
                                    </Button>
                                )}
                            </div>
                        )}
                    </div>
                    <div className="recording-verification">{verificationControls}</div>
                </section>
            )}
            {received?.request.kind === 'recording' && (
                <>
                    {playback && phase === null && playbackAllowed && (
                        <RecordingPlayer
                            source={playback.source}
                            preparedImage={playback.image}
                            onPrepare={onOpen}
                            expected={{
                                id: received.request.id,
                                producer: '',
                                allowUntrusted: true,
                                unchecked: true,
                            }}
                            disabled={disabled}
                            active={active}
                            autoPrepare
                            verificationControls={verificationControls}
                        />
                    )}
                    <section className="recording-evidence">
                        <ArtifactSourceDetails
                            received={received}
                            summary={summary}
                            disabled={locked}
                            page={page}
                            onPage={onPage}
                            onSave={onSave}
                            showFiles={false}
                            scope={scope}
                            relation={relation}
                        />
                    </section>
                </>
            )}
        </>
    );
}
