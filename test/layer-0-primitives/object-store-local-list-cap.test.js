// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The local object store's `list` bounds how much of the tree it walks.
 *
 * The bound is enforced as `results.length >= max`, and a comparison with a
 * non-number is false at every length, so a bound supplied as a string walked
 * the whole tree while the configuration said it was set. A bound read from an
 * environment variable arrives as a string. An explicit `0` was read as absent
 * and replaced by the default 1000, so the tightest bound could not be asked
 * for.
 *
 * Run standalone: `node test/layer-0-primitives/object-store-local-list-cap.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function run() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "os-local-cap-"));
  try {
    var store = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    for (var i = 0; i < 6; i++) {
      await store.put("things/obj-" + i + ".txt", Buffer.from("body-" + i, "utf8"));
    }

    var all = await store.list("things/");
    check("list without a bound returns every object", all.items.length === 6,
          String(all.items.length));

    var two = await store.list("things/", { maxResults: 2 });
    check("a numeric bound stops the walk at that many", two.items.length === 2,
          String(two.items.length));

    var none = await store.list("things/", { maxResults: 0 });
    check("a bound of 0 returns nothing, rather than being read as absent and " +
          "replaced by the default",
          none.items.length === 0, String(none.items.length));

    function refused(opts) {
      return store.list("things/", opts).then(
        function () { return null; },
        function (e) { return e; }
      );
    }
    check("a non-numeric bound is refused rather than walking the whole tree",
          (await refused({ maxResults: "2" })) !== null,
          "accepted maxResults \"2\"");
    check("a bound that is not a number at all is refused",
          (await refused({ maxResults: "abc" })) !== null);
    check("a negative bound is refused", (await refused({ maxResults: -1 })) !== null);
    check("a fractional bound is refused", (await refused({ maxResults: 1.5 })) !== null);
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[object-store-local-list-cap] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
