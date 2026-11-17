import type { KeepAlivePolicy } from './keepalive';

export interface ConnectionActions {
    keepAliveSettings(): KeepAlivePolicy;
    setKeepAlive(interval: string): Promise<KeepAlivePolicy>;
    disconnect(): void;
}

export interface TerminalActions extends ConnectionActions {
    eof(): boolean;
    signal(value: 'INT' | 'TERM'): boolean;
}
