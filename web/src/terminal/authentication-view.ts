import type { LoginStep, Scope } from '../remember';

export interface AuthenticationView {
    readonly id: number;
    readonly scope: Scope;
    readonly user: string;
    readonly step: LoginStep | null;
    readonly pending: boolean;
    readonly remembering: boolean;
    readonly message: string | null;
    readonly provider: LoginStep | null;
    readonly onAnswer: (value: string) => void;
    readonly onCancel: () => void;
}
