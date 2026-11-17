import { RememberMeError } from './protocol';

export type RememberMePolicy = 'forbidden' | 'allowed' | 'allowedAndEnabledByDefault' | 'enforced';

export function rememberMePolicy(value: unknown): RememberMePolicy {
    if (value === undefined) {
        return 'forbidden';
    }
    if (
        value === 'forbidden' ||
        value === 'allowed' ||
        value === 'allowedAndEnabledByDefault' ||
        value === 'enforced'
    ) {
        return value;
    }
    throw new RememberMeError('unavailable');
}

export function rememberMeEnabled(policy: RememberMePolicy | undefined, choice?: boolean): boolean {
    if (policy === undefined || policy === 'forbidden') {
        return false;
    }
    return policy === 'enforced' || (choice ?? policy === 'allowedAndEnabledByDefault');
}
