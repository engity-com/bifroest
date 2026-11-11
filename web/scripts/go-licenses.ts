import { execFileSync } from 'node:child_process';

export interface GoLicenseFile {
    path: string;
    sha256: string;
    text: string;
}

export interface GoLicenseModule {
    module: string;
    license: string;
    files: GoLicenseFile[];
}

// Use the native release tooling and its shared license policy. Go fetches the
// selected module versions through its usual go.mod/go.sum-verified module cache.
export function browserGoLicenses(cwd: string, entry: string): GoLicenseModule[] {
    const [hostOS, hostArch] = execFileSync('go', ['env', 'GOHOSTOS', 'GOHOSTARCH'], {
        cwd,
        encoding: 'utf8',
    })
        .trim()
        .split(/\s+/u);
    return JSON.parse(
        execFileSync('go', ['run', './cmd/build', 'browser-licenses', `--package=${entry}`], {
            cwd,
            env: { ...process.env, GOOS: hostOS, GOARCH: hostArch, CGO_ENABLED: '0' },
            encoding: 'utf8',
            maxBuffer: 8 << 20,
        }),
    );
}
