const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

const script = readFileSync(join(__dirname, "../docs/assets/upgrade.js"), "utf8");
const page = readFileSync(join(__dirname, "../docs/setup/upgrade.md"), "utf8");
const latest = { title: "Latest (0.7.7)", path: "/" };

async function render(release, metadata, pathname = "/setup/upgrade/", navigation = "material", ok = true) {
  const headline = { dataset: { release }, innerText: "Upgrade from previous minor versions" };
  const hint = { hidden: true, append(...parts) { this.parts = parts; } };
  const requests = [];
  let load;
  const document = {
    readyState: navigation === "loading" ? "loading" : "complete",
    querySelector() { return headline; },
    getElementById() { return hint; },
    createElement() { return {}; },
    addEventListener(event, callback) {
      assert.equal(event, "DOMContentLoaded");
      load = callback;
    },
  };
  const context = {
    document,
    location: { pathname },
    async fetch(url) {
      requests.push(url);
      if (metadata instanceof Error) throw metadata;
      return { ok, async json() { return metadata; } };
    },
  };
  if (navigation === "material") context.document$ = { subscribe(callback) { load = callback; } };
  runInNewContext(script, context);
  if (load) await load();
  else await new Promise(setImmediate);
  return { headline, hint, requests };
}

test("upgrade page uses release macro without hardcoded release numbers", () => {
  assert.match(page, /^# .*\{: #upgrade-notes \.upgrade-notes-headline data-release="<<release_name\(\)>>" \}/m);
  assert.doesNotMatch(page, /v\d+\.\d+\.\d+/);
});

test("root uses release metadata for predecessor, even when missing from filtered index", async () => {
  const { headline, hint, requests } = await render("v0.10.2", {
    isLatest: true, latest, previous: "v0.8.12", previousMajorMinor: "v0.8",
  });
  assert.deepEqual(requests, ["/release.json"]);
  assert.equal(headline.innerText, "Upgrade from v0.8.x to v0.10.2");
  assert.equal(hint.parts[1].href, "/v0.8.12/setup/upgrade/");
  assert.equal(hint.parts[1].textContent, "v0.8.x upgrade notes");
  assert.equal(hint.hidden, false);
});

test("beta and directly opened older versions request their own metadata", async () => {
  for (const [release, previous, pathname, target] of [
    ["v1.0.0-beta1", "v0.7.7", "/v1.0.0-beta1/setup/upgrade/", "/v0.7.7/setup/"],
    ["v0.8.1", "v0.7.8", "/v0.8.1/setup/upgrade/", "/v0.7.8/setup/"],
  ]) {
    const { headline, hint, requests } = await render(release, {
      isLatest: false, latest, previous, previousMajorMinor: "v0.7",
    }, pathname);
    assert.deepEqual(requests, [`/${release}/release.json`]);
    assert.equal(headline.innerText, `Upgrade from v0.7.x to ${release}`);
    assert.equal(hint.parts[1].href, target);
    assert.equal(hint.parts[1].textContent, "v0.7.x setup guide");
  }
});

test("upgrade predecessor is independent of optional isLatest and latest", async () => {
  for (const metadata of [
    { previous: "v0.7.7", previousMajorMinor: "v0.7" },
    { latest: null, previous: "v0.7.7", previousMajorMinor: "v0.7" },
  ]) {
    const { headline, hint } = await render("v1.0.0-beta1", metadata, "/v1.0.0-beta1/setup/upgrade/");
    assert.equal(headline.innerText, "Upgrade from v0.7.x to v1.0.0-beta1");
    assert.equal(hint.parts[1].href, "/v0.7.7/setup/");
    assert.equal(hint.hidden, false);
  }
});

test("works with standard navigation and DOMContentLoaded", async () => {
  for (const navigation of ["complete", "loading"]) {
    const { hint, requests } = await render("v0.8.0", {
      isLatest: false, latest, previous: "v0.7.7", previousMajorMinor: "v0.7",
    }, "/v0.8.0/setup/upgrade/", navigation);
    assert.deepEqual(requests, ["/v0.8.0/release.json"]);
    assert.equal(hint.hidden, false);
  }
});

test("hides hint without a valid tag or usable release metadata", async () => {
  for (const release of ["latest", "v1.0.0-rc1", "v1.0.0-beta.1", "v1.0.0-beta01"]) {
    assert.deepEqual((await render(release, {})).requests, []);
  }
  for (const [metadata, ok] of [
    [{}, false], [new Error("offline"), true], [{ isLatest: false }, true],
    [{ isLatest: false, previous: "v0.7.7", previousMajorMinor: "v0.8" }, true],
  ]) {
    const result = await render("v0.8.0", metadata, "/", "material", ok);
    assert.equal(result.hint.hidden, true);
    assert.equal(result.headline.innerText, "Upgrade from previous minor versions");
  }
});
