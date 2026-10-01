const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const { join } = require("node:path");

const partial = readFileSync(join(__dirname, "../docs/.theme/partials/javascripts/outdated.html"), "utf8");

test("outdated banner resolves relative bases on root and versioned pages", () => {
  for (const [baseUrl, location, expected] of [
    [".", "http://127.0.0.1:8000/", "http://127.0.0.1:8000/"],
    ["../..", "http://127.0.0.1:8000/setup/upgrade/", "http://127.0.0.1:8000/"],
    ["../..", "https://bifroest.engity.org/v0.7.6/setup/upgrade/", "https://bifroest.engity.org/v0.7.6/"],
  ]) {
    const banner = { hidden: true };
    let scope;
    const script = partial.replace("{{ base_url }}", baseUrl).replace(/^<script>|<\/script>\s*$/g, "");
    runInNewContext(script, {
      URL,
      location,
      document: { querySelector: () => banner },
      sessionStorage: {},
      __md_get(_key, _storage, base) {
        scope = base;
        return true;
      },
    });
    assert.equal(scope.href, expected);
    assert.equal(banner.hidden, false);
  }
});
