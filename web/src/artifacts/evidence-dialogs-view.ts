import type { RecordingSummary } from '../management/protocol';
import type { Message } from '../ui/messages';
import type { EvidenceDetailsState } from './evidence-details';
import type { LocalKeyInputFields } from './local-key-input-view';
import type { ReceivedArtifact } from './protocol';

export interface EvidenceSettingsView {
    readonly level: 'outer' | 'private';
    readonly checked: boolean;
    readonly producer: string;
    readonly reported: boolean;
    readonly auditScope?: 'complete' | 'captured-prefix';
    onLevel(value: 'outer' | 'private'): void;
    onChecked(value: boolean): void;
    onProducer(value: string): void;
    onAuditScope?(value: 'complete' | 'captured-prefix'): void;
}
export interface EvidenceSourceView {
    readonly received: ReceivedArtifact | null;
    readonly summary: RecordingSummary | null;
    readonly page: number;
    onPage(value: number): void;
    onSave(data: Blob, filename: string): void;
}

// Commands express explicit user gestures, not access/worker capabilities.
// The view cannot inspect a credential value or initiate an implicit request.
export interface EvidenceDialogsView {
    readonly notice: Message | null;
    readonly locked: boolean;
    readonly source: EvidenceSourceView;
    readonly decryption: {
        readonly open: boolean;
        readonly key: LocalKeyInputFields;
        close(): void;
        unlock(): void;
    };
    readonly verification: {
        readonly open: boolean;
        readonly disabled: boolean;
        readonly source: string;
        readonly kind: 'audit' | 'recording';
        readonly input: 'fresh' | 'received' | null;
        readonly settings: EvidenceSettingsView;
        readonly key: LocalKeyInputFields;
        readonly showKey: boolean;
        readonly cached: boolean;
        readonly canForget: boolean;
        readonly canReplace: boolean;
        readonly export: { readonly data: Blob; readonly filename: string } | null;
        selectInput(value: 'fresh' | 'received'): void;
        close(): void;
        start(): void;
        forget(): void;
        replace(): void;
    };
    readonly details: {
        readonly open: boolean;
        readonly retryDisabled: boolean;
        readonly state: EvidenceDetailsState;
        readonly changeSettings: (() => void) | null;
        readonly retryOpen: (() => void) | null;
        close(): void;
    };
}
