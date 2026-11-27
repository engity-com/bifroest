async function showUpgradePredecessor() {
    const headline = document.querySelector('h1.upgrade-notes-headline[data-release]');
    if (!headline) {
        return;
    }
    const hint = document.getElementById('upgrade-predecessor');

    const release = headline.dataset.release || '';
    if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:alpha|beta)[1-9]\d*)?$/.test(release)) {
        return;
    }

    // An explicitly documented compatibility baseline must not be broadened
    // to a whole series by release-index metadata.
    const baseline = headline.dataset.baseline;
    if (baseline) {
        if (/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(baseline)) {
            headline.textContent = `Upgrade from ${baseline} to ${release}`;
        }
        return;
    }

    try {
        const prefix = /^\/(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\//.exec(location.pathname)?.[1];
        const response = await fetch(prefix ? `/${prefix}/release.json` : '/release.json');
        if (!response.ok) {
            return;
        }
        const metadata = await response.json();
        if (
            !/^v\d+\.\d+\.\d+$/.test(metadata?.previous) ||
            !/^v\d+\.\d+$/.test(metadata.previousMajorMinor) ||
            !metadata.previous.startsWith(`${metadata.previousMajorMinor}.`)
        ) {
            return;
        }

        const series = `${metadata.previousMajorMinor}.x`;
        if (document.querySelector('h1.upgrade-notes-headline[data-release]') !== headline) {
            return;
        }
        headline.textContent = `Upgrade from ${series} to ${release}`;

        if (!hint || document.getElementById('upgrade-predecessor') !== hint) {
            return;
        }
        // The v0.7.x site predates public upgrade notes.
        const hasNotes = metadata.previousMajorMinor !== 'v0.7';
        const link = document.createElement('a');
        link.href = `/${metadata.previous}/setup/${hasNotes ? 'upgrade/' : ''}`;
        link.textContent = `${series} ${hasNotes ? 'upgrade notes' : 'setup guide'}`;
        hint.append(
            `If your current Bifröst is not ${series}, consult the `,
            link,
            ' as well before upgrading.',
        );
        hint.hidden = false;
    } catch (_) {
        // No predecessor hint without usable release metadata.
    }
}

if (typeof document$ !== 'undefined' && typeof document$.subscribe === 'function') {
    document$.subscribe(showUpgradePredecessor);
} else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', showUpgradePredecessor);
} else {
    showUpgradePredecessor();
}
