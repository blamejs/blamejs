// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `b.objectStore.buildBackend` requires, and what names the backend it
 * returns.
 *
 * `protocol` was documented as defaulting to `local`. It does not default: the
 * dispatcher refuses a missing protocol, and the `fallbackProtocol` the store
 * registers is only named in the text of a deferred-protocol refusal. Had the
 * documented default been real, a config with a typo'd key would have built a
 * local store under whatever directory the rest of the config implied.
 *
 * A config omitted entirely raised a bare `Error` carrying no code, while
 * every other refusal from this module, including the one `bucketOps.create`
 * raises for the same mistake, carried an `ObjectStoreError` and a code. An
 * operator catching by code could not catch the first one.
 *
 * Run standalone: `node test/layer-0-primitives/object-store-backend-identity.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs = require("node:fs");
var path = require("node:path");
var os = require("node:os");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _refusal(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

async function run() {
  var rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "os-identity-"));
  try {
    var noConfig = _refusal(function () { return b.objectStore.buildBackend(); });
    check("a missing config is refused with a code, not a bare Error",
          !!noConfig && noConfig.code === "objectstore/bad-opt",
          "got " + (noConfig && (noConfig.code || noConfig.constructor.name)));
    check("and bucketOps.create refuses the same mistake the same way",
          (_refusal(function () { return b.objectStore.bucketOps.create(); }) || {}).code ===
            "objectstore/bad-opt");

    var noProto = _refusal(function () {
      return b.objectStore.buildBackend({ rootDir: rootDir });
    });
    check("an omitted protocol is refused rather than defaulted to local",
          !!noProto && noProto.code === "protocol-dispatcher/missing-protocol",
          "got " + (noProto && (noProto.code || noProto.message)));

    var badProto = _refusal(function () {
      return b.objectStore.buildBackend({ protocol: "s3", rootDir: rootDir });
    });
    check("an unknown protocol is refused and the message lists the known ones",
          !!badProto && badProto.code === "protocol-dispatcher/unknown-protocol" &&
            /local/.test(badProto.message) && /sigv4/.test(badProto.message),
          badProto && badProto.message);

    // The control for the three refusals above: the same config with the
    // protocol named builds, so each refusal is about the protocol and not
    // about the directory or the module failing to load at all.
    var store = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir });
    check("naming the protocol builds the backend", typeof store.put === "function");
    check("the backend's name defaults to the protocol", store.name === "local");
    check("the backend reports the protocol it was built for", store.protocol === "local");
    check("the breaker is named protocol:root, so two roots trip independently",
          store.breaker.name === "local:" + path.resolve(rootDir),
          store.breaker.name);

    var second = b.objectStore.buildBackend({ protocol: "local", rootDir: rootDir, name: "archive" });
    check("an explicit name takes over the backend's name", second.name === "archive");
    check("and the breaker's", second.breaker.name === "archive");

    check("classifications default to any, and residency to unrestricted",
          store.servesClassification("phi") === true &&
            store.residencyTag === "unrestricted");
  } finally {
    try { fs.rmSync(rootDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[object-store-backend-identity] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
