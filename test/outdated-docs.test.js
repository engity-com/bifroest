const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

const script = readFileSync(join(__dirname, "../docs/assets/versions.js"), "utf8");
const template = readFileSync(join(__dirname, "../docs/.theme/main.html"), "utf8");
const config = readFileSync(join(__dirname, "../mkdocs.yml"), "utf8");

const latest = { title: "0.7.7", path: "/" };
const versions = [
  { tag: "v1.0.0-beta1", title: "1.0.0-beta1", path: "/v1.0.0-beta1/", prerelease: true },
  { tag: "v0.7.7", title: latest.title, path: latest.path, aliases: ["/latest/", "/v0.7.7/"], latest: true },
];

async function render(pathname, manifests, index = versions) {
  const button = { events: {}, addEventListener(event, callback) { this.events[event] = callback; } };
  const list = {
    items: [],
    replaceChildren() { this.items = []; },
    append(item) { this.items.push(item); },
  };
  const picker = {
    hidden: true,
    events: {},
    addEventListener(event, callback) { this.events[event] = callback; },
    querySelector(selector) {
      return { ".md-version__current": button, ".md-version__list": list }[selector];
    },
  };
  const content = { replaceChildren(...parts) { this.parts = parts; } };
  const banner = { hidden: true, querySelector: () => content };
  const topic = { append(child) { child.parentElement = this; } };
  let load;
  const requests = [];
  const context = {
    location: { pathname },
    document: {
      querySelector(selector) {
        return {
          ".md-version": picker,
          "[data-md-component=outdated]": banner,
          ".md-header__topic": topic,
        }[selector];
      },
      createElement: () => ({ append(child) { this.link = child; } }),
    },
    document$: { subscribe(callback) { load = callback; } },
    async fetch(url) {
      requests.push(url);
      const value = url === "/versions-v2.json" ? index : manifests[url];
      if (value instanceof Error) throw value;
      return { ok: value !== undefined, async json() { return value; } };
    },
  };
  runInNewContext(script, context);
  await load();
  return {
    button, list, picker, banner, content, topic, requests,
    get bannerLink() { return content.parts?.[1]; },
    async open(event = "mouseenter") {
      await (event === "mouseenter" ? picker.events[event] : button.events[event])();
    },
    async navigate(path) { context.location.pathname = path; await load(); },
  };
}

test("uses Material's picker appearance without enabling its versions.json integration", () => {
  assert.doesNotMatch(config, /provider: mike/);
  assert.match(config, /assets\/versions\.js/);
  assert.match(template, /data-md-component="outdated"/);
  assert.doesNotMatch(template, /You're not viewing|pre-release version|Click here to go/);
  assert.match(template, /class="md-version__current"/);
  assert.match(template, /class="md-version__list"/);
  assert.doesNotMatch(script, /versions\.json/);
});

test("root and stable aliases use release metadata without loading the menu", async () => {
  for (const pathname of ["/", "/setup/upgrade/", "/latest/setup/", "/v0.7.7/setup/"]) {
    const url = pathname.startsWith("/v0.7.7/") ? "/v0.7.7/release.json" : "/release.json";
    const result = await render(pathname, { [url]: { isLatest: true, latest } });
    assert.deepEqual(result.requests, [url]);
    assert.equal(result.button.textContent, "Latest (0.7.7)");
    assert.equal(result.picker.parentElement, result.topic);
    assert.equal(result.picker.hidden, false);
    assert.equal(result.banner.hidden, true);
  }
});

test("beta banner describes a pre-release and uses the release manifest's latest path", async () => {
  const path = "/v1.0.0-beta1/setup/upgrade/";
  const releaseUrl = "/v1.0.0-beta1/release.json";
  const result = await render(path, {
    [releaseUrl]: { isLatest: false, prerelease: true, latest: { title: "0.9.3", path: "/v0.9.3/" } },
  }, [versions[0]]);
  assert.deepEqual(result.requests, [releaseUrl]);
  assert.equal(result.button.textContent, "1.0.0-beta1");
  assert.equal(result.banner.hidden, false);
  assert.equal(result.content.parts[0], "You're viewing a pre-release version. ");
  assert.equal(result.bannerLink.href, "/v0.9.3/");
  assert.equal(result.bannerLink.title, "Latest (0.9.3)");
  assert.equal(result.bannerLink.link.textContent, "Click here to go to latest stable version.");

  await result.open();
  assert.deepEqual(result.requests, [releaseUrl, "/versions-v2.json"]);
  assert.equal(result.list.items[0].link.href, "/v1.0.0-beta1/");
  assert.equal(result.list.items[0].link.textContent, "1.0.0-beta1");
});

test("an old filtered-out version stays identified before and after opening the menu", async () => {
  const releaseUrl = "/v0.7.5/release.json";
  const result = await render("/v0.7.5/setup/", {
    [releaseUrl]: { isLatest: false, latest },
  });
  assert.equal(result.button.textContent, "0.7.5");
  assert.equal(result.banner.hidden, false);
  assert.equal(result.content.parts[0], "You're not viewing the latest version. ");
  assert.equal(result.bannerLink.link.textContent, "Click here to go to latest.");
  assert.deepEqual(result.requests, [releaseUrl]);
  await result.open("focus");
  assert.equal(result.button.textContent, "0.7.5");
  assert.equal(result.list.items.some(item => item.link.href === "/v0.7.5/"), false);
  assert.equal(result.list.items[1].link.href, "/");
  assert.equal(result.list.items[1].link.className, "md-version__link");
  assert.equal(result.list.items[1].link.textContent, "Latest (0.7.7)");
  await result.open("click");
  assert.equal(result.requests.filter(url => url === "/versions-v2.json").length, 1);
});

test("focusing and clicking an open menu link keeps its DOM node for browser navigation", async () => {
  const result = await render("/", { "/release.json": { isLatest: true, latest } });
  await result.open();
  const item = result.list.items[0];
  const link = item.link;
  assert.equal(link.href, "/v1.0.0-beta1/");
  assert.equal(result.picker.events.focusin, undefined);
  // Browser focus and subsequent openings must not replace the clicked anchor.
  await result.open("focus");
  await result.open("click");
  assert.equal(result.list.items[0], item);
  assert.equal(result.list.items[0].link, link);
});

test("loaded menu is reused after instant navigation without another index request", async () => {
  const result = await render("/v0.7.5/setup/", {
    "/v0.7.5/release.json": { isLatest: false, latest },
    "/v1.0.0-beta1/release.json": { isLatest: false, latest },
  });
  await result.open();
  await result.navigate("/v1.0.0-beta1/setup/");
  assert.equal(result.button.textContent, "1.0.0-beta1");
  await result.open();
  assert.equal(result.requests.filter(url => url === "/versions-v2.json").length, 1);
});

test("unknown path or invalid manifest never selects the first menu item or shows the banner", async () => {
  const result = await render("/unknown/", { "/release.json": { isLatest: false } }, [versions[0]]);
  assert.equal(result.button.textContent, "Version");
  assert.equal(result.banner.hidden, true);
  await result.open();
  assert.equal(result.button.textContent, "Version");
});

test("missing latest keeps the banner hidden even when isLatest is absent", async () => {
  for (const release of [
    { isLatest: false },
    { isLatest: false, latest: null },
    { isLatest: false, latest: {} },
    { latest: null },
    {},
  ]) {
    const result = await render("/v0.7.5/setup/", { "/v0.7.5/release.json": release });
    assert.deepEqual(result.requests, ["/v0.7.5/release.json"]);
    assert.equal(result.button.textContent, "0.7.5");
    assert.equal(result.banner.hidden, true);
    await result.open();
    assert.equal(result.button.textContent, "0.7.5");
  }
});

test("absent isLatest shows the banner when latest provides a usable target", async () => {
  for (const pathname of ["/", "/v1.0.0-beta1/setup/"]) {
    const releaseUrl = pathname === "/" ? "/release.json" : "/v1.0.0-beta1/release.json";
    const result = await render(pathname, { [releaseUrl]: { latest } });
    assert.deepEqual(result.requests, [releaseUrl]);
    assert.equal(result.banner.hidden, false);
    assert.equal(result.content.parts[0], "You're not viewing the latest version. ");
    assert.equal(result.bannerLink.href, latest.path);
    assert.equal(result.bannerLink.title, "Latest (0.7.7)");
  }
});

test("prerelease flag selects the pre-release banner even without isLatest", async () => {
  const result = await render("/v1.0.0-beta1/setup/", {
    "/v1.0.0-beta1/release.json": { prerelease: true, latest },
  });
  assert.equal(result.banner.hidden, false);
  assert.equal(result.content.parts[0], "You're viewing a pre-release version. ");
  assert.equal(result.bannerLink.href, "/");
  assert.equal(result.bannerLink.link.textContent, "Click here to go to latest stable version.");
});
