import {
    type SpawnSyncOptionsWithStringEncoding,
    type SpawnSyncReturns,
    spawnSync,
} from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { requirePinnedNode } from './tool-versions.ts';

// Successful Phase 1 run 45472956311, Browser assets and inventory job
// 138726110604, mise test:go:browser (Linux, CGO_ENABLED=0). These are measured
// top-level seconds, including all subtests, fresh profiles and process restarts.
export const browserTestSeconds: Readonly<Record<string, number>> = {
    TestBrowserDummyBannerStartsLinesAtColumnZero: 1.38,
    TestBrowserManagementDrawerGridAndKeepAlive: 4.76,
    TestBrowserManagementSessionRecordingEventRelations: 4.47,
    TestBrowserArtifactResponseObserverPreservesFlushFailure: 0,
    TestBrowserArtifactTransferUsesGoWasmAndPostDriverCompletion: 191.59,
    TestBrowserRememberMeClientAgainstRealHttpsAndWebSocket: 0.98,
    TestBrowserKeepAliveUiLockedEditableFlowIsolationAndPersistence: 4.45,
    TestBrowserPublicKeyUiWasmLocalImportProofCertificatesAndRemember: 14.85,
    TestBrowserPublicKeyAlgorithmsUiOpenShells: 19.12,
    TestBrowserPublicKeyCertificateWithoutPtyUiCannotOpenShell: 3.92,
    TestBrowserPublicKeyUiSafeFailureDiagnostics: 8.05,
    TestBrowserSlugRouterAndLoginOptionsKeepWorkspacesAndInputModes: 11.65,
    TestBrowserManagementActionsUiConfirmationDisconnectDisposeAndLostReply: 13.38,
    TestBrowserOidcCodeRedirectWithRealCookies: 39.23,
    TestBrowserUiPreferencesRequireNamesAndRememberOnlySuccessfulOriginalNames: 4.22,
    TestBrowserLocalRepositoryPasswordRememberMeUiAcrossProfileRestart: 8.06,
    TestBrowserLocalRepositoryInteractiveRememberMeUiAcrossProfileRestart: 12.19,
    TestBrowserRootDirectoryDoesNotOfferRootAsLoginSlug: 1.07,
    TestBrowserSinglePublishedDirectorySelectsSlugWithoutAuthentication: 1.08,
    TestBrowserActualRootAccessRemainsSelectable: 1,
    TestBrowserTabHistoryPreservesEntryAliasAndRootDefinitionDefaults: 10.72,
    TestBrowserLoginUiWithRememberRecoveryAndStrictCsp: 8.08,
    TestBrowserLoginUiReplacesDamagedRememberMeKeyWithoutWarning: 4.87,
    TestBrowserLoginUiPreservesDisabledRequestingName: 1.28,
    TestBrowserLoginUiDoesNotOfferImpossibleCredentialMethods: 0.93,
    TestBrowserBootstrapMetadataRetryDoesNotStartAuthentication: 0.99,
    TestBrowserHiddenSlugsUserHintsAndFieldValidationNeverLeakIntoRequestURLs: 1.39,
    TestBrowserSlugNavigationRetiresStoppedAuthenticationAtTabLimit: 8.91,
    TestBrowserTerminalUiFreshExecutionResizeSignalsExitAndDisconnect: 25.42,
    TestBrowserCompactWorkspaceUiContextMenusMouseAndFreshLogin: 12.63,
    TestBrowserTerminalTabsUiBoundsAndCanceledInitialization: 6.04,
    TestBrowserTerminalGrantExpiryUiKeepsExistingShell: 8.95,
    TestBrowserTerminalLostLogoutUiDoesNotClaimSuccessOrReplay: 2.14,
    TestBrowserInteractiveLoginUiPlainTextEchoAndCancel: 19.42,
    TestBrowserOidcDeviceLoginUiVerifiedIdentityAndRemember: 5.09,
    TestBrowserOidcDeviceCancelUiStopsProviderRequest: 2.23,
    TestBrowserInteractiveLostClaimUiDoesNotReplay: 5.48,
    TestBrowserManagementUiStructuredTablesAndActorIsolation: 8.14,
    TestBrowserProfileResetUiClosesOnlyConfirmedTabsAndRevokesAcrossSlugsAndWindows: 6.65,
    TestBrowserConnectionWorkspaceUiKeepsFlowActorAndManagementContexts: 36.08,
    TestBrowserConnectionWorkspaceUiCancellationAndUnknownDoNotStartSiblingAccess: 7.96,
    TestBrowserManagementWorkspaceUiRetiresHiddenPreparationAndPinsActionOwner: 7.86,
    TestBrowserManagementWorkspaceUiCloseDialogCannotRetireUnknownOwner: 8.17,
    TestBrowserManagementForcedReadUiWithholdsUnexposedIdentity: 4.6,
    TestBrowserManagementForcedAuditReadUiPagesWithoutTransfer: 4.56,
    TestBrowserManagementForcedVersionUiKeepsShortOutputAndEscapesMetadata: 4.48,
    TestBrowserManagementForcedDisconnectUiHasNoInspectionGrant: 5.8,
    TestBrowserManagementForcedDisposeUiLostReplyIsNotReplayed: 6.16,
};

// New/platform-specific tests are never excluded for lacking a measurement.
// Ten seconds is a planning estimate only, not a measured duration or deadline.
export const unprofiledBrowserTestSeconds = 10;
const browserTestName = /^TestBrowser[\p{L}\p{N}_]*$/u;

export interface BrowserShard {
    index: number;
    total: number;
}

export interface BrowserTestShard {
    tests: string[];
    estimatedSeconds: number;
}

export function parseBrowserShard(args: readonly string[]): BrowserShard {
    if (args.length === 0) {
        return { index: 1, total: 1 };
    }
    const match =
        args.length === 2 && args[0] === '--shard'
            ? /^([1-9][0-9]*)\/([1-9][0-9]*)$/u.exec(args[1] ?? '')
            : null;
    const index = Number(match?.[1]);
    const total = Number(match?.[2]);
    if (!Number.isSafeInteger(index) || !Number.isSafeInteger(total) || index > total) {
        throw new Error('Usage: node scripts/browser-go-tests.ts [--shard INDEX/TOTAL]');
    }
    return { index, total };
}

function validateBrowserTests(tests: readonly string[]): void {
    if (tests.length === 0) {
        throw new Error('Go did not list any TestBrowser tests');
    }
    const seen = new Set<string>();
    for (const name of tests) {
        if (!browserTestName.test(name) || seen.has(name)) {
            throw new Error(`Invalid or duplicate browser test: ${name}`);
        }
        seen.add(name);
    }
}

export function parseBrowserTestList(output: string): string[] {
    const tests = output
        .split(/\r?\n/u)
        .filter((line) => line.trimStart().startsWith('TestBrowser'));
    validateBrowserTests(tests);
    return tests;
}

export function verifyBrowserTestPlan(
    tests: readonly string[],
    plan: readonly BrowserTestShard[],
): void {
    validateBrowserTests(tests);
    const assigned = plan.flatMap((shard) => shard.tests);
    validateBrowserTests(assigned);
    const expected = new Set(tests);
    if (
        plan.length === 0 ||
        plan.some((shard) => shard.tests.length === 0) ||
        assigned.length !== tests.length ||
        assigned.some((name) => !expected.has(name))
    ) {
        throw new Error('Browser shard plan must cover every listed test exactly once');
    }
}

export function planBrowserTests(tests: readonly string[], total: number): BrowserTestShard[] {
    validateBrowserTests(tests);
    if (!Number.isSafeInteger(total) || total < 1 || total > tests.length) {
        throw new Error('Browser shard count must be between one and the listed test count');
    }
    const seconds = (name: string) => browserTestSeconds[name] ?? unprofiledBrowserTestSeconds;
    const ordered = [...tests].sort(
        (a, b) => seconds(b) - seconds(a) || (a < b ? -1 : a > b ? 1 : 0),
    );
    const plan: BrowserTestShard[] = Array.from({ length: total }, () => ({
        tests: [],
        estimatedSeconds: 0,
    }));
    for (const name of ordered) {
        const target = plan.reduce((best, next) =>
            next.estimatedSeconds < best.estimatedSeconds ||
            (next.estimatedSeconds === best.estimatedSeconds &&
                next.tests.length < best.tests.length)
                ? next
                : best,
        );
        target.tests.push(name);
        target.estimatedSeconds += seconds(name);
    }
    for (const shard of plan) {
        shard.tests.sort();
    }
    verifyBrowserTestPlan(tests, plan);
    return plan;
}

export function browserTestPattern(tests: readonly string[]): string {
    validateBrowserTests(tests);
    // Go identifiers contain no regexp metacharacters; never select by substring.
    return `^(${tests.join('|')})$`;
}

type GoResult = Pick<SpawnSyncReturns<string>, 'status' | 'signal' | 'error' | 'stdout'>;
type CommandRunner = (
    command: string,
    args: string[],
    options: SpawnSyncOptionsWithStringEncoding,
) => GoResult;

function goExitCode(result: GoResult): number {
    if (result.error !== undefined) {
        throw result.error;
    }
    return result.signal === null ? (result.status ?? 1) : 1;
}

export function runBrowserGoTests(
    args: readonly string[],
    {
        run = (command, argv, options) => spawnSync(command, argv, options),
        env = process.env,
        log = console.log,
    }: { run?: CommandRunner; env?: NodeJS.ProcessEnv; log?: (message: string) => void } = {},
): number {
    const shard = parseBrowserShard(args);
    requirePinnedNode();
    const parallelism = env.GO_TEST_PARALLELISM ?? '2';
    if (!/^[1-9][0-9]*$/u.test(parallelism) || !Number.isSafeInteger(Number(parallelism))) {
        throw new Error('GO_TEST_PARALLELISM must be a positive safe integer');
    }
    const options: SpawnSyncOptionsWithStringEncoding = {
        cwd: fileURLToPath(new URL('../../', import.meta.url)),
        env: {
            ...env,
            BIFROEST_TEST_BROWSER_UI: '1',
            BIFROEST_TEST_BROWSER_CLIENT: '1',
            BIFROEST_TEST_NODE: process.execPath,
        },
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'inherit'],
    };
    const listed = run(
        'go',
        ['test', `-p=${parallelism}`, '-list', '^TestBrowser', './pkg/service'],
        options,
    );
    const listExit = goExitCode(listed);
    if (listExit !== 0) {
        return listExit;
    }
    const tests = parseBrowserTestList(listed.stdout ?? '');
    const plan = planBrowserTests(tests, shard.total);
    const selected = plan[shard.index - 1];
    if (selected === undefined) {
        throw new Error('Browser shard is missing from the verified test plan');
    }
    for (const [index, entry] of plan.entries()) {
        log(
            `Browser Go shard ${index + 1}/${shard.total}: ${entry.tests.length} tests, ${entry.estimatedSeconds.toFixed(2)}s estimated`,
        );
    }
    const unprofiled = tests.filter((name) => browserTestSeconds[name] === undefined);
    if (unprofiled.length !== 0) {
        log(
            `Unprofiled tests (modeled ${unprofiledBrowserTestSeconds}s each): ${unprofiled.join(', ')}`,
        );
    }
    log(`Running browser Go shard ${shard.index}/${shard.total}: ${selected.tests.join(', ')}`);
    const testArgs = [
        '--format',
        'standard-verbose',
        '--jsonfile',
        'var/test-report/browser.jsonl',
        '--junitfile',
        'var/test-report/browser.xml',
        '--',
        `-p=${parallelism}`,
        '-count=1',
        '-timeout=20m',
        '-run',
        browserTestPattern(selected.tests),
        './pkg/service',
    ];
    return goExitCode(run('gotestsum', testArgs, { ...options, stdio: 'inherit' }));
}

if (import.meta.main) {
    try {
        process.exitCode = runBrowserGoTests(process.argv.slice(2));
    } catch (error) {
        console.error(error instanceof Error ? error.message : error);
        process.exitCode = 1;
    }
}
