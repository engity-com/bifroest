import type { WebglAddon as XtermWebglAddon } from '@xterm/addon-webgl';
import type { Terminal as XtermTerminal } from '@xterm/xterm';
import type { WebAccess } from '../src/remember';
import type { DrawerDiagnostics } from './drawer-diagnostics.ts';
import type { LoginControlDiagnostics } from './login-control-diagnostics.ts';

// Browser-only fixture observations, initialized by the owning addInitScript.
// The owning fixture initializes each observation before use.
declare global {
    var bifroestLoginControlDiagnostics: LoginControlDiagnostics | undefined;
    var bifroestDrawerDiagnostics: DrawerDiagnostics | undefined;
    var testPreparationReceipt:
        | { status: number; target?: { flow: string; id: string }; error?: string }
        | undefined;
    interface Worker {
        terminated: boolean;
        workerName: string;
        requests: string[];
        playbackDigests: Promise<string>[];
        ready: boolean;
        sentVerification: boolean;
        failureCode: string | null;
        receivedDigest?: string;
        transferFailureReason?: string | null;
    }

    interface Window {
        cspViolations: string[];
        artifactStorageWrites: { store: string; key: unknown }[];
        artifactURLs: Set<string>;
        ownedWorkers: Worker[];
        managementTargetAccess: WebAccess;
        managementTargetSockets: WebSocket[];
        targetAccess: WebAccess;
        targetSockets: WebSocket[];
        fixtureInline: boolean;
        providerInjected: boolean;
        versionInjected: boolean;
        untrustedInlineRan: boolean;
        nativeCompositionEndTrusted: boolean;
        routeWorkspaceSentinel: string;
        singleRootInitialHistoryLength: number;
        singleRootHistoryEvents: { method: string; path: string }[];
        slugHistoryEvents: { method: string; path: string; view: number | null }[];
        terminalContextEvents: boolean[];
        testUiConsoleErrors: unknown[][];
        testTerminalKeyBubbles: number;
        testTerminalKeys: { key: string; type: string; prevented: boolean }[];
        testTabTouchEvents: {
            type: string;
            primary: boolean | null;
            button: number | null;
            pointerType: string | null;
            tab: string | null;
            modal: boolean;
        }[];
        Terminal: typeof XtermTerminal;
        WebglAddon: { WebglAddon: typeof XtermWebglAddon };
    }
}
