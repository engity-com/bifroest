// The server supplies the mount path, never a query parameter or saved login.
// Workers derive it from their own module URL under the same assets directory.
export function pathPrefix(): string {
    let value = '';
    if (typeof document !== 'undefined') {
        value =
            document
                .querySelector?.('meta[name="bifroest-path-prefix"]')
                ?.getAttribute('content') ?? '';
    } else {
        const path = new URL(import.meta.url).pathname;
        const index = path.lastIndexOf('/assets/');
        if (index >= 0) {
            value = path.slice(0, index);
        }
    }
    if (
        value !== '' &&
        (value.length > 1024 ||
            !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(value) ||
            value.split('/').some((part) => part === '.' || part === '..'))
    ) {
        throw new Error('Invalid Bifröst mount path');
    }
    return value;
}

export function publicPath(path: string): string {
    if (!path.startsWith('/') || path.startsWith('//')) {
        throw new Error('Invalid Bifröst path');
    }
    return pathPrefix() + path;
}

export function internalPath(path: string): string {
    const prefix = pathPrefix();
    if (prefix === '') {
        return path;
    }
    if (path === prefix) {
        return '/';
    }
    return path.startsWith(`${prefix}/`) ? path.slice(prefix.length) : '';
}

export function deploymentKey(value: string): string {
    const prefix = pathPrefix();
    return prefix === '' ? value : `bifroest-path-${encodeURIComponent(prefix)}:${value}`;
}

export function ownsPreferenceKey(value: string): boolean {
    return pathPrefix() === ''
        ? value.startsWith('bifroest-') && !value.startsWith('bifroest-path-')
        : value.startsWith(deploymentKey(''));
}
