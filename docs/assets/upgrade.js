async function showUpgradePredecessor() {
  const hint = document.getElementById("upgrade-predecessor");
  if (!hint) return;

  const own = /^v(\d+)\.(\d+)\.(\d+)$/.exec(hint.dataset.release || "");
  if (!own) return;

  try {
    const response = await fetch("/versions.json");
    if (!response.ok) return;
    const versions = await response.json();
    if (!Array.isArray(versions)) return;

    // The versions index is ordered newest first. Its ".." entry names the latest release in its title.
    let previous;
    for (const entry of versions) {
      if (!entry || typeof entry.version !== "string") continue;
      const latest = entry.version === ".." && entry.latest === true
        ? /^Latest \((\d+\.\d+\.\d+)\)$/.exec(entry.title)?.[1]
        : null;
      const version = latest ? `v${latest}` : entry.version;
      const match = /^v(\d+)\.(\d+)\.(\d+)$/.exec(version);
      if (match && (Number(match[1]) < Number(own[1]) ||
        (Number(match[1]) === Number(own[1]) && Number(match[2]) < Number(own[2])))) {
        previous = { version, match };
        break;
      }
    }
    if (!previous) return;

    const [, major, minor] = previous.match;
    const series = `v${major}.${minor}.x`;
    // The v0.7.x site predates public upgrade notes.
    const hasNotes = !(Number(major) === 0 && Number(minor) === 7);
    const link = document.createElement("a");
    link.href = `/${previous.version}/setup/${hasNotes ? "upgrade/" : ""}`;
    link.textContent = `${series} ${hasNotes ? "upgrade notes" : "setup guide"}`;
    if (document.getElementById("upgrade-predecessor") !== hint) return;
    hint.append(`If your current Bifröst is not ${series}, consult the `, link, " as well before upgrading.");
    hint.hidden = false;
  } catch (_) {
    // No predecessor hint without a usable versions index.
  }
}

if (typeof document$ !== "undefined" && typeof document$.subscribe === "function") {
  document$.subscribe(showUpgradePredecessor);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", showUpgradePredecessor);
} else {
  showUpgradePredecessor();
}
