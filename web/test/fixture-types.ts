import type { Page, WebSocket } from 'playwright';
import type {} from './harness-globals.d.ts';

export type { Page } from 'playwright';
export type Login = (page: Page, remember: boolean, user?: string) => Promise<void>;
export type Logout = (page: Page) => Promise<void>;
export type Restart = () => Promise<Page>;

export interface SocketObserverPage {
    on(event: 'websocket', listener: (socket: WebSocket) => void): unknown;
}

export interface ManagementCall {
    path: string;
    body: Record<string, string | undefined>;
    channel?: string;
    slug?: string;
}

export interface NetworkObservation {
    path: string;
    status?: number;
    method?: string;
    error?: string | undefined;
    failure?: string | undefined;
    type?: string | undefined;
    encoding?: string | undefined;
    length?: string | undefined;
    mediaType?: string | undefined;
    stage?: string;
    id?: number | undefined;
}

export interface LoginRequest {
    slug: string;
    user: string;
    method?: string | undefined;
}

export interface NativeProbe {
    marker: string;
    sid: string;
    user: string;
    pty: boolean;
    columns: number;
    rows: number;
    session: string;
    connection: string;
    execution: string;
    content: string;
}
