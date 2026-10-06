// The published index is a filtered menu, not an inventory of all published versions.
let menuEntries;
let menuRequest;
let observedPicker;
let renderedPicker;
let renderedPathname;

function versionPrefix(pathname) {
  return /^\/(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\//.exec(pathname)?.[1];
}

function versionTitle(title, latest) {
  return latest ? `Latest (${title})` : title;
}

function renderVersionMenu() {
  const picker = document.querySelector(".md-version");
  const button = picker?.querySelector(".md-version__current");
  const list = picker?.querySelector(".md-version__list");
  if (!button || !list || !menuEntries) return;

  const pathname = location.pathname;
  if (renderedPicker === picker && renderedPathname === pathname) return;
  const paths = entry => [entry.path, ...(Array.isArray(entry.aliases) ? entry.aliases : [])];
  const current = menuEntries.find(entry => paths(entry)
    .some(path => path !== "/" && pathname.startsWith(path))) ||
    (!versionPrefix(pathname) && menuEntries.find(entry => paths(entry).includes("/")));
  if (current) button.textContent = versionTitle(current.title, current.latest === true);

  list.replaceChildren();
  for (const entry of menuEntries) {
    const item = document.createElement("li");
    item.className = "md-version__item";
    const link = document.createElement("a");
    link.className = "md-version__link";
    link.href = entry.path;
    link.textContent = versionTitle(entry.title, entry.latest === true);
    item.append(link);
    list.append(item);
  }
  renderedPicker = picker;
  renderedPathname = pathname;
}

async function openVersionMenu() {
  if (!menuRequest) {
    menuRequest = fetch("/versions-v2.json")
      .then(response => {
        if (!response.ok) throw new Error("Versions index unavailable");
        return response.json();
      })
      .then(versions => {
        if (!Array.isArray(versions)) throw new Error("Invalid versions index");
        menuEntries = versions.filter(entry => entry && typeof entry.tag === "string" &&
          typeof entry.title === "string" && typeof entry.path === "string" &&
          entry.path.startsWith("/") && entry.path.endsWith("/"));
      })
      .catch(() => { menuRequest = undefined; });
  }
  await menuRequest;
  renderVersionMenu();
}

async function showVersions() {
  const picker = document.querySelector(".md-version");
  const button = picker?.querySelector(".md-version__current");
  const banner = document.querySelector("[data-md-component=outdated]");
  if (!picker || !button || !banner) return;

  const topic = document.querySelector(".md-header__topic");
  if (topic && picker.parentElement !== topic) topic.append(picker);
  if (observedPicker !== picker) {
    picker.addEventListener("mouseenter", openVersionMenu);
    button.addEventListener("focus", openVersionMenu);
    button.addEventListener("click", openVersionMenu);
    observedPicker = picker;
  }

  const pathname = location.pathname;
  const prefix = versionPrefix(pathname);
  button.textContent = prefix ? prefix.slice(1) : "Version";
  picker.hidden = false;
  banner.hidden = true;
  if (menuEntries) renderVersionMenu();

  try {
    const response = await fetch(prefix ? `/${prefix}/release.json` : "/release.json");
    if (!response.ok) return;
    const release = await response.json();
    if (location.pathname !== pathname) return;
    const latest = release?.latest;
    if (typeof latest?.title !== "string" || typeof latest.path !== "string" ||
      !latest.path.startsWith("/") || !latest.path.endsWith("/")) return;

    if (release.isLatest === true) button.textContent = versionTitle(latest.title, true);
    if (release.isLatest !== true) {
      const prerelease = release.prerelease === true;
      const link = document.createElement("a");
      link.href = latest.path;
      link.title = versionTitle(latest.title, true);
      const strong = document.createElement("strong");
      strong.textContent = prerelease
        ? "Click here to go to latest stable version."
        : "Click here to go to latest.";
      link.append(strong);
      banner.querySelector(".md-banner__inner").replaceChildren(
        prerelease
          ? "You're viewing a pre-release version. "
          : "You're not viewing the latest version. ",
        link
      );
      banner.hidden = false;
    }
  } catch (_) {
    // A missing release manifest must not trigger a misleading outdated banner.
  }
}

if (typeof document$ !== "undefined" && typeof document$.subscribe === "function") {
  document$.subscribe(showVersions);
} else if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", showVersions);
} else {
  showVersions();
}
