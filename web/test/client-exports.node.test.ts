import { expect, it } from 'vitest';
import {
    BrowserBinding,
    BrowserClient,
    createRecordingVerificationBatch,
    EvidenceError,
    prepareRecordingPlayback,
    RememberMeError,
    verifyArtifact,
    WebAccess,
} from '../src/client';

it('assembles the standalone browser client API without merging its domain entry points', () => {
    for (const exported of [
        BrowserClient,
        WebAccess,
        BrowserBinding,
        RememberMeError,
        EvidenceError,
        verifyArtifact,
        createRecordingVerificationBatch,
        prepareRecordingPlayback,
    ]) {
        expect(typeof exported).toBe('function');
    }
});
