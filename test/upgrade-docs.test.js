const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

const script = readFileSync(join(__dirname, "../docs/assets/upgrade.js"), "utf8");
const page = readFileSync(join(__dirname, "../docs/setup/upgrade.md"), "utf8");

async function render(release, versions, ok = true, navigation = "material") {
  const headline = { dataset: { release }, innerText: "Upgrade from previous minor versions" };
  const hint = {
    dataset: { release },
    hidden: true,
    append(...parts) { this.parts = parts; },
  };
  let requested = false;
  let load;
  const context = {
    document: {
      readyState: navigation === "loading" ? "loading" : "complete",
      querySelector(selector) {
        assert.equal(selector, "h1.upgrade-notes-headline[data-release]");
        return headline;
      },
      getElementById() { return hint; },
      createElement() { return {}; },
      addEventListener(event, callback) {
        assert.equal(event, "DOMContentLoaded");
        load = callback;
      },
    },
    async fetch(url) {
      requested = true;
      assert.equal(url, "/versions.json");
      if (versions instanceof Error) throw versions;
      return { ok, async json() { return versions; } };
    },
  };
  if (navigation === "material") {
    context.document$ = { subscribe(callback) { load = callback; } };
  }
  runInNewContext(script, context);
  if (load) await load();
  else await new Promise(setImmediate);
  return { headline, hint, requested };
}

test("upgrade page uses release macro without hardcoded release numbers", () => {
  assert.match(page, /^# .*\{: #upgrade-notes \.upgrade-notes-headline data-release="<<release_name\(\)>>" \}/m);
  assert.match(page, /Upgrade from v0\.7\.x to <<release_name\(\)>>/);
  assert.doesNotMatch(page, /v\d+\.\d+\.\d+/);
});

test("selects the first lower minor numerically, ignoring aliases and prereleases", async () => {
  const { headline, hint } = await render("v0.10.2", [
    { version: ".." },
    { version: "v0.10.1" },
    { version: "v0.9.4" },
    { version: "v0.9.5-rc.1" },
    { version: "v0.8.12" },
  ]);
  assert.equal(hint.hidden, false);
  assert.equal(headline.innerText, "Upgrade from v0.9.x to v0.10.2");
  assert.equal(hint.parts[0], "If your current Bifröst is not v0.9.x, consult the ");
  assert.equal(hint.parts[1].href, "/v0.9.4/setup/upgrade/");
  assert.equal(hint.parts[1].textContent, "v0.9.x upgrade notes");
});

test("links to the setup guide for the minor without public upgrade notes", async () => {
  const { headline, hint } = await render("v0.8.0", [{ version: ".." }, { version: "v0.7.8" }, { version: "v0.7.7" }]);
  assert.equal(headline.innerText, "Upgrade from v0.7.x to v0.8.0");
  assert.equal(hint.parts[1].href, "/v0.7.8/setup/");
  assert.equal(hint.parts[1].textContent, "v0.7.x setup guide");
});

test("beta docs resolve the current stable latest patch from its alias", async () => {
  const { headline, hint } = await render("v1.0.0-beta1", [
    { version: "..", title: "Latest (0.7.7)", aliases: ["latest"], latest: true },
    { version: "v0.7.6" },
  ]);
  assert.equal(hint.hidden, false);
  assert.equal(headline.innerText, "Upgrade from v0.7.x to v1.0.0-beta1");
  assert.equal(hint.parts[1].href, "/v0.7.7/setup/");
});

test("alpha and later beta docs skip prereleases and select the stable lower series", async () => {
  for (const release of ["v1.0.0-alpha2", "v1.0.0-beta10"]) {
    const { hint } = await render(release, [
      { version: "..", title: "Latest (0.7.7)", latest: true },
      { version: "v1.0.0-beta1" },
      { version: "v1.0.0-alpha1" },
      { version: "v0.7.8-rc.1" },
      { version: "v0.7.7" },
      { version: "v0.7.6" },
    ]);
    assert.equal(hint.hidden, false);
    assert.equal(hint.parts[1].href, "/v0.7.7/setup/");
  }
});

test("works without Material navigation on an already loaded page or DOMContentLoaded", async () => {
  for (const navigation of ["complete", "loading"]) {
    const { hint, requested } = await render("v0.8.0", [{ version: "v0.7.7" }], true, navigation);
    assert.equal(requested, true);
    assert.equal(hint.hidden, false);
    assert.equal(hint.parts[1].href, "/v0.7.7/setup/");
  }
});

test("hides hint without a release tag or usable versions index", async () => {
  const dev = await render("latest", [{ version: "v0.7.7" }]);
  assert.equal(dev.requested, false);
  assert.equal(dev.hint.hidden, true);
  for (const release of ["v1.0.0-rc1", "v1.0.0-beta.1", "v1.0.0-beta01"]) {
    const invalid = await render(release, [{ version: "v0.7.7" }]);
    assert.equal(invalid.requested, false);
  }
  for (const [versions, ok] of [[[], false], [new Error("offline"), true], [[{ version: ".." }], true]]) {
    const result = await render("v0.8.0", versions, ok);
    assert.equal(result.hint.hidden, true);
    assert.equal(result.headline.innerText, "Upgrade from previous minor versions");
  }
});
