export function copyDeviceCode(code: string): Promise<boolean> {
    try {
        return navigator.clipboard.writeText(code).then(
            () => true,
            () => false,
        );
    } catch {
        return Promise.resolve(false);
    }
}

// Called synchronously on Enter/click, not on arrival of a provider message.
// Do not await clipboard permissions before opening: that loses popup activation.
export function openDeviceLogin(url: string): boolean {
    let opened = false;
    let popup: Window | null = null;
    try {
        popup = window.open('about:blank', '_blank');
        if (popup) {
            popup.opener = null;
            popup.location.replace(url);
            opened = true;
        }
    } catch {
        /* The ordinary verification link remains usable. */
        try {
            popup?.close();
        } catch {
            /* Do not leave a waiting tab after a failed navigation. */
        }
    }
    return opened;
}
