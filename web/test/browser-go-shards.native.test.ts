import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
    browserTestPattern,
    browserTestSeconds,
    parseBrowserShard,
    parseBrowserTestList,
    planBrowserTests,
    runBrowserGoTests,
    unprofiledBrowserTestSeconds,
    verifyBrowserTestPlan,
} from '../scripts/browser-go-tests.ts';
import { required } from './required.ts';

const measuredTests = Object.keys(browserTestSeconds);
const result = (status: number | null = 0, stdout = measuredTests.join('\n')) => ({
    status,
    stdout,
    signal: null,
});

test('shard parsing accepts only the documented complete positive safe-integer pair', () => {
    assert.deepEqual(parseBrowserShard([]), { index: 1, total: 1 });
    assert.deepEqual(parseBrowserShard(['--shard', '1/3']), { index: 1, total: 3 });
    assert.deepEqual(parseBrowserShard(['--shard', '3/3']), { index: 3, total: 3 });
    for (const args of [
        ['--shard'],
        ['--shard=1/3'],
        ['1/3'],
        ['--other', '1/3'],
        ['--shard', '1/3', 'extra'],
        ['--shard', '1/3', '--shard', '2/3'],
        ...[
            '',
            '0/3',
            '1/0',
            '4/3',
            '-1/3',
            '1/-3',
            '01/3',
            '1/03',
            '1.0/3',
            '1/3x',
            '1/3\n',
            ' 1/3',
            '1/3 ',
            '1/3/4',
            'NaN/3',
            '1/Infinity',
            '9007199254740992/9007199254740992',
            '1/9007199254740992',
        ].map((value) => ['--shard', value]),
    ]) {
        assert.throws(() => parseBrowserShard(args), /Usage/u, JSON.stringify(args));
    }
});

test('dynamic Go discovery rejects empty, duplicate, malformed and subtest lists', () => {
    assert.deepEqual(
        parseBrowserTestList(
            'TestBrowserOne\r\nTestBrowserTwo\r\nok  example/pkg/service  0.01s\r\n',
        ),
        ['TestBrowserOne', 'TestBrowserTwo'],
    );
    for (const output of [
        '',
        'ok  example/pkg/service 0.01s',
        'TestBrowserOne\nTestBrowserOne',
        'TestBrowserOne/subtest',
        'TestBrowserOne|Other',
        'TestBrowserOne ',
        ' TestBrowserOne\nTestBrowserTwo',
    ]) {
        assert.throws(() => parseBrowserTestList(output));
    }
});

test('the measured three-shard plan covers all 48 real HTTPS top-level tests exactly once', () => {
    assert.equal(measuredTests.length, 48);
    const plan = planBrowserTests(measuredTests, 3);
    verifyBrowserTestPlan(measuredTests, plan);
    assert.deepEqual(plan, planBrowserTests([...measuredTests].reverse(), 3));
    assert.deepEqual(plan.flatMap((shard) => shard.tests).sort(), [...measuredTests].sort());
    assert.equal(new Set(plan.flatMap((shard) => shard.tests)).size, measuredTests.length);
    assert.deepEqual(required(plan[0]).tests, [
        'TestBrowserArtifactTransferUsesGoWasmAndPostDriverCompletion',
    ]);
    for (const shard of plan) {
        assert(shard.estimatedSeconds >= 189 && shard.estimatedSeconds <= 192);
        const pattern = new RegExp(browserTestPattern(shard.tests), 'u');
        assert.deepEqual(measuredTests.filter((name) => pattern.test(name)).sort(), shard.tests);
    }
    assert(
        Math.abs(plan.reduce((total, shard) => total + shard.estimatedSeconds, 0) - 570.48) < 0.001,
    );
});

test('new tests and platform-specific PAM tests join the plan without a weight allowlist', () => {
    const added = [
        'TestBrowserNewSecurityAssertion',
        'TestBrowserLocalPamPasswordRememberMeUiAcrossProfileRestart',
        'TestBrowserLocalPamInteractiveRememberMeUiAcrossProfileRestart',
    ];
    const all = [...measuredTests, ...added];
    const plan = planBrowserTests(all, 3);
    verifyBrowserTestPlan(all, plan);
    assert.deepEqual(plan.flatMap((shard) => shard.tests).sort(), [...all].sort());
    assert(
        Math.abs(
            plan.reduce((sum, shard) => sum + shard.estimatedSeconds, 0) -
                570.48 -
                added.length * unprofiledBrowserTestSeconds,
        ) < 0.001,
    );
    const selected = new RegExp(browserTestPattern(['TestBrowserOne']), 'u');
    assert(selected.test('TestBrowserOne'));
    assert(!selected.test('TestBrowserOneMore'));
    assert(!selected.test('OtherTestBrowserOne'));
    assert(!selected.test('TestBrowserOne/subtest'));
});

test('every supported shard count retains complete disjoint ownership, including zero-cost tests', () => {
    for (let total = 1; total <= measuredTests.length; total++) {
        const plan = planBrowserTests(measuredTests, total);
        assert.equal(plan.length, total);
        verifyBrowserTestPlan(measuredTests, plan);
        assert.deepEqual(plan.flatMap((shard) => shard.tests).sort(), [...measuredTests].sort());
    }
});

test('test-plan verification refuses omissions, duplicate ownership and unlisted tests', () => {
    const tests = ['TestBrowserOne', 'TestBrowserTwo'];
    const entry = (...names: string[]) => ({ tests: names, estimatedSeconds: 1 });
    for (const plan of [
        [],
        [entry()],
        [entry('TestBrowserOne')],
        [entry('TestBrowserOne'), entry('TestBrowserOne')],
        [entry('TestBrowserOne'), entry('TestBrowserOther')],
        [entry('TestBrowserOne', 'TestBrowserTwo'), entry()],
    ]) {
        assert.throws(() => verifyBrowserTestPlan(tests, plan));
    }
    for (const total of [0, -1, 0.5, 3, Number.NaN, Number.POSITIVE_INFINITY]) {
        assert.throws(() => planBrowserTests(tests, total));
    }
    assert.throws(() => planBrowserTests(['TestBrowserOne', 'TestBrowserOne'], 1));
    assert.throws(() => browserTestPattern([]));
});

test('runner discovers dynamically, forces both browser opt-ins and preserves the original Go budget', () => {
    for (const args of [[], ['--shard', '1/3'], ['--shard', '2/3'], ['--shard', '3/3']]) {
        let calls = 0;
        const messages: string[] = [];
        assert.equal(
            runBrowserGoTests(args, {
                env: {
                    GO_TEST_PARALLELISM: '1',
                    GOMAXPROCS: '2',
                    CGO_ENABLED: '0',
                    BIFROEST_TEST_BROWSER_UI: '0',
                    BIFROEST_TEST_BROWSER_CLIENT: '0',
                    BIFROEST_TEST_NODE: '/wrong/node',
                },
                log: (message) => messages.push(message),
                runGo: (argv, options) => {
                    calls++;
                    assert.equal(options.cwd, fileURLToPath(new URL('../../', import.meta.url)));
                    assert.equal(options.env?.BIFROEST_TEST_BROWSER_UI, '1');
                    assert.equal(options.env?.BIFROEST_TEST_BROWSER_CLIENT, '1');
                    assert.equal(options.env?.BIFROEST_TEST_NODE, process.execPath);
                    assert.equal(options.env?.GOMAXPROCS, '2');
                    assert.equal(options.env?.CGO_ENABLED, '0');
                    if (calls === 1) {
                        assert.deepEqual(argv, [
                            'test',
                            '-p=1',
                            '-list',
                            '^TestBrowser',
                            './pkg/service',
                        ]);
                        return result();
                    }
                    const shard = parseBrowserShard(args);
                    const expected = required(
                        planBrowserTests(measuredTests, shard.total)[shard.index - 1],
                    );
                    assert.deepEqual(argv, [
                        'test',
                        '-p=1',
                        '-v',
                        '-count=1',
                        '-timeout=20m',
                        '-run',
                        browserTestPattern(expected.tests),
                        './pkg/service',
                    ]);
                    assert.equal(options.stdio, 'inherit');
                    return result();
                },
            }),
            0,
        );
        assert.equal(calls, 2);
        assert(messages.some((message) => message.startsWith('Running browser Go shard')));
    }
});

test('default parallelism stays two and unprofiled tests are visibly modeled', () => {
    let calls = 0;
    const messages: string[] = [];
    assert.equal(
        runBrowserGoTests([], {
            env: {},
            log: (message) => messages.push(message),
            runGo: (argv) => {
                calls++;
                assert.equal(argv[1], '-p=2');
                return result(0, 'TestBrowserNew');
            },
        }),
        0,
    );
    assert.equal(calls, 2);
    assert(messages.includes('Unprofiled tests (modeled 10s each): TestBrowserNew'));
});

test('optional JSON reporting preserves discovery, scope, opt-ins, deadline and failing exits', () => {
    for (const status of [0, 1, 23, null]) {
        let calls = 0;
        assert.equal(
            runBrowserGoTests(['--shard', '2/3'], {
                env: { BIFROEST_TEST_REPORT: 'var/test-report/browser', GO_TEST_PARALLELISM: '1' },
                log: () => {},
                runGo: (argv, options) => {
                    calls++;
                    if (calls === 1) {
                        assert.deepEqual(argv, [
                            'test',
                            '-p=1',
                            '-list',
                            '^TestBrowser',
                            './pkg/service',
                        ]);
                        return result();
                    }
                    assert.deepEqual(argv, [
                        'run',
                        '-p=1',
                        './cmd/testreport',
                        'run',
                        '--output',
                        'var/test-report/browser',
                        '--',
                        'go',
                        'test',
                        '-p=1',
                        '-json',
                        '-count=1',
                        '-timeout=20m',
                        '-run',
                        browserTestPattern(required(planBrowserTests(measuredTests, 3)[1]).tests),
                        './pkg/service',
                    ]);
                    assert.equal(options.env?.BIFROEST_TEST_BROWSER_UI, '1');
                    assert.equal(options.env?.BIFROEST_TEST_BROWSER_CLIENT, '1');
                    assert.equal(options.env?.BIFROEST_TEST_NODE, process.execPath);
                    assert.equal(options.stdio, 'inherit');
                    return result(status);
                },
            }),
            status ?? 1,
        );
        assert.equal(calls, 2);
    }
});

test('list/test exits, signals and spawn failures cannot become a green browser run', () => {
    for (const status of [1, 17, null]) {
        for (const failedCall of [1, 2]) {
            let calls = 0;
            assert.equal(
                runBrowserGoTests([], {
                    env: {},
                    log: () => {},
                    runGo: () => result(++calls === failedCall ? status : 0),
                }),
                status ?? 1,
            );
            assert.equal(calls, failedCall);
        }
    }
    for (const failedCall of [1, 2]) {
        let calls = 0;
        assert.equal(
            runBrowserGoTests([], {
                env: {},
                log: () => {},
                runGo: () =>
                    ++calls === failedCall ? { ...result(null), signal: 'SIGTERM' } : result(),
            }),
            1,
        );
        calls = 0;
        assert.throws(
            () =>
                runBrowserGoTests([], {
                    env: {},
                    log: () => {},
                    runGo: () =>
                        ++calls === failedCall
                            ? { ...result(null), error: new Error('spawn failed') }
                            : result(),
                }),
            /spawn failed/u,
        );
    }
});

test('invalid arguments, parallelism, listing or empty shards stop before test execution', () => {
    let calls = 0;
    const runGo = () => {
        calls++;
        return result(0, 'TestBrowserOne');
    };
    assert.throws(() => runBrowserGoTests(['--shard', '0/3'], { runGo }));
    for (const value of ['', '0', '-1', '1x', '1.5', '9007199254740992']) {
        assert.throws(() =>
            runBrowserGoTests([], {
                runGo,
                env: { GO_TEST_PARALLELISM: value },
            }),
        );
    }
    for (const report of [
        '',
        ' ',
        '.',
        '..',
        '../outside',
        'var/../../outside',
        resolve('absolute'),
    ]) {
        assert.throws(() =>
            runBrowserGoTests([], {
                runGo,
                env: { BIFROEST_TEST_REPORT: report },
            }),
        );
    }
    assert.equal(calls, 0);
    assert.throws(() => runBrowserGoTests(['--shard', '2/3'], { runGo }));
    assert.equal(calls, 1);
    for (const stdout of ['', 'TestBrowserOne\nTestBrowserOne']) {
        assert.throws(() =>
            runBrowserGoTests([], {
                runGo: () => result(0, stdout),
            }),
        );
    }
});

test('the direct CLI fails closed on malformed shard input without starting Go', () => {
    const child = spawnSync(process.execPath, ['scripts/browser-go-tests.ts', '--shard', '0/3'], {
        cwd: fileURLToPath(new URL('../', import.meta.url)),
        encoding: 'utf8',
    });
    assert.equal(child.status, 1);
    assert.match(child.stderr, /Usage/u);
    assert.equal(child.stdout, '');
});
