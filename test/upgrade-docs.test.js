const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

const script = readFileSync(join(__dirname, "../docs/assets/upgrade.js"), "utf8");
const page = readFileSync(join(__dirname, "../docs/setup/upgrade.md"), "utf8");

async function render(release, versions, ok = true, navigation = "material") {
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
  return { hint, requested };
}

test("upgrade page uses release macro without hardcoded release numbers", () => {
  assert.match(page, /## From the previous minor series to <<release_name\(\)>>/);
  assert.match(page, /data-release="<<release_name\(\)>>"/);
  assert.doesNotMatch(page, /v\d+\.\d+(?:\.\d+|\.x)?/);
});

test("selects the first lower minor numerically, ignoring aliases and prereleases", async () => {
  const { hint } = await render("v0.10.2", [
    { version: ".." },
    { version: "v0.10.1" },
    { version: "v0.9.4" },
    { version: "v0.9.5-rc.1" },
    { version: "v0.8.12" },
  ]);
  assert.equal(hint.hidden, false);
  assert.equal(hint.parts[0], "If your current Bifröst is not v0.9.x, consult the ");
  assert.equal(hint.parts[1].href, "/v0.9.4/setup/upgrade/");
  assert.equal(hint.parts[1].textContent, "v0.9.x upgrade notes");
});

test("links to the setup guide for the minor without public upgrade notes", async () => {
  const { hint } = await render("v0.8.0", [{ version: ".." }, { version: "v0.7.8" }, { version: "v0.7.7" }]);
  assert.equal(hint.parts[1].href, "/v0.7.8/setup/");
  assert.equal(hint.parts[1].textContent, "v0.7.x setup guide");
});

test("pre-release docs resolve the current latest patch from its alias", async () => {
  const { hint } = await render("v0.8.0", [
    { version: "..", title: "Latest (0.7.7)", aliases: ["latest"], latest: true },
    { version: "v0.7.6" },
  ]);
  assert.equal(hint.parts[1].href, "/v0.7.7/setup/");
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
  assert.equal((await render("v0.8.0", [], false)).hint.hidden, true);
  assert.equal((await render("v0.8.0", new Error("offline"))).hint.hidden, true);
  assert.equal((await render("v0.8.0", [{ version: ".." }])).hint.hidden, true);
});
