export interface BrowserInputs {
  readonly revision: string;
  readonly dirty: boolean;
  readonly bun: string;
  readonly node: string;
  readonly inputs: readonly {
    readonly name: string;
    readonly bytes: number;
    readonly sha256: string;
  }[];
}
export function captureBrowserInputs(root?: string): BrowserInputs;
export function writeBrowserRelease(output: URL, root?: string, snapshot?: BrowserInputs): void;
