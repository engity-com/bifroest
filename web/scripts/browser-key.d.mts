export function buildBrowserKey(output: URL): void;
export function browserGoToolchain(output: URL): {
  cwd: string;
  go(args: string[]): string;
  version: string;
  runtimeHash: string;
  runtimeSource: string;
};
