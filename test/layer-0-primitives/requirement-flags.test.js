// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An option that names a REQUIREMENT is validated, not reinterpreted.
 *
 * `var required = opts.requireX === true;` turns every value that is not the
 * boolean `true` into `false`, and says nothing. For an option that GRANTS
 * something that fails closed and costs the operator a feature. For an option
 * that REQUIRES something it fails open: the protection the configuration asked
 * for is simply absent.
 *
 * The values that reach these options are rarely booleans in the first place. A
 * setting read from an environment variable is the string `"true"`, and a
 * setting read from a config file is whatever that file's parser produced. Every
 * one of those was accepted and read as "not required".
 *
 * This walks the requirement flags across the primitives that hold them, rather
 * than testing each primitive's own file, because the defect is one shape
 * repeated: a reviewer who finds it in one place has found it in all of them.
 * The companion structural check in codebase-patterns.test.js fails on the next
 * requirement-shaped option added without a validation.
 *
 * Run standalone: node test/layer-0-primitives/requirement-flags.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// What an environment variable or a config file hands a primitive when the
// operator wrote something that means "on" to them. None of these is a boolean,
// and every one of them was read as false.
var NON_BOOLEANS = ["true", "yes", "on", 1, "1", "false", 0, "off", "no"];

// Each subject names a primitive, a call that exercises the option, and the
// requirement flags it reads. `call(flagName, value)` must invoke the real
// exported path with that option set.
function _subjects() {
  return [
    {
      name:  "b.restore.create",
      flags: ["requireSignature"],
      call:  function (flag, value) {
        var opts = {
          dataDir: "/nonexistent-restore-data-dir",
          passphrase: "a-passphrase-for-the-option-walk",
          storage: { readBundle: function () {}, listBundles: function () { return []; },
                     hasBundle: function () { return false; } },
        };
        opts[flag] = value;
        return b.restore.create(opts);
      },
    },
    {
      name:  "b.ntpCheck.checkDrift",
      flags: ["requireNts"],
      call:  function (flag, value) {
        var opts = { servers: [], timeoutMs: 1 };
        opts[flag] = value;
        return b.ntpCheck.checkDrift(opts);
      },
    },
    {
      name:  "b.security.assertProduction",
      flags: ["requireTLS", "requireCSPNonce", "requireCSRF", "requireRateLimit"],
      call:  function (flag, value) {
        var opts = { protocol: "https" };
        opts[flag] = value;
        return b.security.assertProduction(opts);
      },
    },
    {
      name:  "b.cbor.decode",
      flags: ["requireDeterministic"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.cbor.decode(b.cbor.encode({ a: 1 }), opts);
      },
    },
    {
      name:  "b.safeMountInfo.parse",
      flags: ["strict"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.safeMountInfo.parse("", opts);
      },
    },
    {
      name:  "b.eat.verify",
      flags: ["requireDebugDisabled"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.eat.verify("not-a-token", opts);
      },
    },
    {
      name:  "b.restoreBundle.extract",
      flags: ["requireSignature"],
      call:  function (flag, value) {
        var opts = { bundleDir: "/nonexistent-extract-bundle-dir" };
        opts[flag] = value;
        return b.restoreBundle.extract(opts);
      },
    },
    {
      name:  "b.time.monotonicClock",
      flags: ["strict"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.time.monotonicClock(opts);
      },
    },
    {
      // Not on the `b` surface: the OCSP must-staple gate is reached through the
      // module, and it builds the verifier a TLS socket calls, so a value it
      // cannot read is settled once at build time rather than per handshake.
      name:  "network-tls ocsp.requireMustStaple",
      flags: ["enforceUnconditional"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return require("../../lib/network-tls").ocsp.requireMustStaple(opts);
      },
    },
    // The other direction. A PERMISSION read as `opts.X !== false` stays ON for
    // every value that is not the boolean `false`, so an operator tightening the
    // policy with a string got the loose setting and no warning. These are the
    // resource-isolation policy and the upstream-id trust decision, where that
    // is the difference between refusing a request and serving it.
    {
      name:  "b.middleware.fetchMetadata",
      flags: ["allowSameSite", "allowMissing", "allowedNavigate", "allowCrossSite"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.middleware.fetchMetadata(opts);
      },
    },
    {
      name:  "b.middleware.requestId",
      flags: ["trustUpstream"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.middleware.requestId(opts);
      },
    },
  ];
}

function _codeOf(fn) {
  try {
    var out = fn();
    if (out && typeof out.then === "function") {
      return out.then(function () { return null; }, function (e) { return (e && e.code) || "threw"; });
    }
    return null;
  } catch (e) {
    return (e && e.code) || "threw";
  }
}

// Several of these calls cannot succeed in a unit test: a restore plan wants a
// real bundle, an NTP check wants a server. That does not matter, because what
// is being asserted is a DIFFERENCE. With the flag set to a real boolean the
// call fails its own way, if it fails at all; with the flag set to a string it
// must fail differently, naming the option. Identical outcomes mean the value
// was read rather than checked.
async function testARequirementFlagRefusesANonBoolean() {
  var subjects = _subjects();
  var accepted = [];

  for (var s = 0; s < subjects.length; s += 1) {
    var subject = subjects[s];
    for (var f = 0; f < subject.flags.length; f += 1) {
      var flag = subject.flags[f];
      var baseline = await _codeOf(function () { return subject.call(flag, true); });
      for (var v = 0; v < NON_BOOLEANS.length; v += 1) {
        var value = NON_BOOLEANS[v];
        var code = await _codeOf(function () { return subject.call(flag, value); });
        // The guarantee is that the non-boolean is rejected where the boolean is
        // not. What each primitive calls its refusal is its own business, so the
        // code is not matched against a naming convention: requiring one flagged
        // `ntp/bad-require-nts`, which is a correct refusal.
        var refused = code !== null && code !== baseline;
        if (!refused) {
          accepted.push(subject.name + " " + flag + " = " + JSON.stringify(value) +
                        " -> " + (code === null ? "ACCEPTED" : code) +
                        " (boolean gives " + (baseline === null ? "ACCEPTED" : baseline) + ")");
        }
      }
    }
  }

  check("a requirement flag refuses a value that is not a boolean" +
        (accepted.length ? " (" + accepted.slice(0, 6).join("; ") + ")" : ""),
        accepted.length === 0);
}

async function run() {
  await testARequirementFlagRefusesANonBoolean();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    console.log("[requirement-flags] OK — " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  });
}
