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

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// A .env file holding one key, so the `b.safeEnv.load` subject below can set
// the flag on a key that IS present. That is the case the schema check used to
// skip: the type of `required` was read only on the branch a MISSING key takes,
// so the same schema was an error on a machine without the variable and silence
// on a machine with it.
var _envDir = null;
function _envFileHoldingOneKey() {
  if (_envDir === null) {
    _envDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamejs-requirement-flags-"));
    nodeFs.writeFileSync(nodePath.join(_envDir, "present.env"), "PRESENT_KEY=hello\n", "utf8");
  }
  return nodePath.join(_envDir, "present.env");
}

// What an environment variable or a config file hands a primitive when the
// operator wrote something that means "on" to them. None of these is a boolean,
// and every one of them was read as false.
var NON_BOOLEANS = ["true", "yes", "on", 1, "1", "false", 0, "off", "no"];

// A registered ACR for the step-up subject, so its requirement resolves.
var STEP_UP_ACR = "urn:blamejs:requirement-flags:loa2";

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
      // `forbidProxy` sits in this same function beside the four `require*`
      // options, tightens the same way, and was read `=== true` while they were
      // being fixed. The word `require` was never what made those fail open.
      name:  "b.security.assertProduction",
      flags: ["requireTLS", "requireCSPNonce", "requireCSRF", "requireRateLimit", "forbidProxy"],
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
    // The receiver's NAME is not what makes a value operator-supplied. Scoping
    // the structural check to `opts` missed every one of these: a role entry, a
    // route's middleware options, a policy spec, an env schema.
    {
      name:  "b.permissions.create role entry",
      flags: ["requireMfa"],
      call:  function (flag, value) {
        var entry = { permissions: ["x:read"] };
        entry[flag] = value;
        return b.permissions.create({ roles: { admin: entry } });
      },
    },
    {
      name:  "b.permissions require() route gate",
      flags: ["requireMfa"],
      call:  function (flag, value) {
        var perms = b.permissions.create({ roles: { admin: { permissions: ["x:read"] } } });
        var mwOpts = {};
        mwOpts[flag] = value;
        return perms.require("x:read", mwOpts);
      },
    },
    {
      name:  "b.sql.createPolicy",
      flags: ["permissive", "allowLiterals"],
      call:  function (flag, value) {
        var spec = { using: "true" };
        spec[flag] = value;
        return b.sql.createPolicy("p", "t", spec, { dialect: "postgres" });
      },
    },
    {
      name:  "b.safeEnv.readVar schema",
      flags: ["required"],
      call:  function (flag, value) {
        var schema = {};
        schema[flag] = value;
        return b.safeEnv.readVar("BLAMEJS_A_NAME_NOTHING_SETS", schema);
      },
    },
    {
      // Same schema, same flag, but on a key the file HOLDS. A schema is one
      // artifact read on every machine, so its shape cannot depend on which
      // variables a given machine happens to set.
      name:  "b.safeEnv.load schema, key present",
      flags: ["required"],
      call:  function (flag, value) {
        var schema = { PRESENT_KEY: { type: "string" } };
        schema.PRESENT_KEY[flag] = value;
        return b.safeEnv.load(_envFileHoldingOneKey(), { expected: schema });
      },
    },
    // The verbs below tighten without being spelled `require`. Each was read
    // `=== true`, so a value that is not a boolean left the tightening off.
    {
      name:  "b.safeEnv.load",
      flags: ["rejectUnknown"],
      call:  function (flag, value) {
        var opts = { expected: {} };
        opts[flag] = value;
        return b.safeEnv.load(_envFileHoldingOneKey(), opts);
      },
    },
    {
      name:  "b.dualControl.create",
      flags: ["forbidSelfApprove"],
      call:  function (flag, value) {
        // A complete opts set, so the boolean check is reached rather than the
        // namespace or cache refusal standing in for it: with an incomplete
        // one, both the boolean and the non-boolean give the same code and the
        // differential cannot tell them apart.
        var opts = {
          namespace:    "requirement-flags",
          cache:        b.cache.create({ backend: "memory", namespace: "requirement-flags-dc" }),
          minApprovers: 2,
        };
        opts[flag] = value;
        return b.dualControl.create(opts);
      },
    },
    {
      name:  "b.mail.transports.console",
      flags: ["redactBcc"],
      call:  function (flag, value) {
        var opts = { stream: { write: function () {} } };
        opts[flag] = value;
        return b.mail.transports.console(opts);
      },
    },
    {
      name:  "b.mcp.sampling.guard",
      flags: ["refuseStopSequences"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.mcp.sampling.guard(opts);
      },
    },
    // A verb can sit anywhere in the name. These carry theirs in the middle or
    // at the end, and a rule anchored at the front of the name reported none of
    // them.
    {
      name:  "b.middleware.requireBoundKey",
      flags: ["tolerateMissingPeerCert"],
      call:  function (flag, value) {
        var opts = { resolver: async function () { return null; } };
        opts[flag] = value;
        return b.middleware.requireBoundKey(opts);
      },
    },
    {
      name:  "b.middleware.requireStepUp",
      flags: ["acceptGrant"],
      call:  function (flag, value) {
        // The requirement names a registered ACR, so the middleware is built
        // rather than refused for a reason that has nothing to do with the flag.
        b.auth.acr.register({ value: STEP_UP_ACR, rank: 2 });
        var opts = { requirement: { acr: STEP_UP_ACR } };
        opts[flag] = value;
        return b.middleware.requireStepUp(opts);
      },
    },
    // A BARE truthy read — `if (opts.allowX)`, `!opts.allowX` — grants the
    // permission for the string "false" exactly as `!!opts.allowX` does. Each
    // of these declares `boolean` in its own documentation.
    {
      name:  "b.safePath.resolve",
      flags: ["allowAbsoluteRel"],
      call:  function (flag, value) {
        var opts = { platform: "linux" };
        opts[flag] = value;
        return b.safePath.resolve("/srv/base", "sub/file.txt", opts);
      },
    },
    {
      name:  "b.safeSql.validateIdentifier",
      flags: ["allowReserved", "allowSqliteInternal"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.safeSql.validateIdentifier("ordinary_name", opts);
      },
    },
    {
      name:  "b.atomicFile.fdSafeReadSync",
      flags: ["allowShortRead"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.atomicFile.fdSafeReadSync("/nonexistent-atomic-file-probe", opts);
      },
    },
    {
      name:  "b.auditChain.verifyPurgeAnchor",
      flags: ["allowUnsigned"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.auditChain.verifyPurgeAnchor(null, opts);
      },
    },
    {
      name:  "b.notify.transports.httpJson",
      flags: ["allowHttp", "allowInternal"],
      call:  function (flag, value) {
        var opts = { url: "https://example.com/hook" };
        opts[flag] = value;
        return b.notify.transports.httpJson(opts);
      },
    },
    // The guards do not check their own options: they hand them to the shared
    // resolver, which refuses a non-boolean for every key whose default is a
    // boolean. Driven through the guards themselves, so what is asserted is
    // what an operator calling them gets.
    {
      name:  "b.guardHtml.validate",
      flags: ["allowComments", "allowImageData"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.guardHtml.validate("<p>x</p>", opts);
      },
    },
    {
      name:  "b.guardSvg.validate",
      flags: ["allowAnimation", "allowImageData", "allowExternalRefs"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.guardSvg.validate("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", opts);
      },
    },
    {
      name:  "b.guardSql.validate",
      flags: ["allowComments", "allowLiterals"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.guardSql.validate("SELECT 1", opts);
      },
    },
    {
      name:  "b.guardYaml.validate",
      flags: ["safeCoreTagsAllowed"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.guardYaml.validate("a: 1", opts);
      },
    },
    {
      name:  "b.guardJson.validate",
      flags: ["requireTopLevelKeyAllowlist"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.guardJson.validate("{}", opts);
      },
    },
    // Tightening options whose verb is none of the ones the structural check
    // knows. They were found by walking every option a module declares
    // `boolean` and reading which way each one fails, rather than by adding
    // more words to a list.
    {
      name:  "b.template.create",
      flags: ["sandbox"],
      call:  function (flag, value) {
        var opts = { viewsDir: ".", sandboxHelpers: {} };
        opts[flag] = value;
        return b.template.create(opts);
      },
    },
    {
      name:  "b.cryptoField.registerTable",
      flags: ["aad"],
      call:  function (flag, value) {
        var opts = { fields: ["secret"], rowIdField: "id" };
        opts[flag] = value;
        return b.cryptoField.registerTable("requirement_flags_probe", opts);
      },
    },
    {
      name:  "b.jsonSchema.compile",
      flags: ["assertFormat"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.jsonSchema.compile({ type: "string", format: "email" }, opts);
      },
    },
    {
      name:  "b.compliance.aiAct.gpai.classify",
      flags: ["designatedSystemicRisk"],
      call:  function (flag, value) {
        var opts = { kind: "gpai" };
        opts[flag] = value;
        return b.compliance.aiAct.gpai.classify(opts);
      },
    },
    {
      // The refusal this option exists for: MTA-STS and TLS-RPT records must
      // carry a field after the version, and a record that ends there matched
      // anyway for every value that was not the boolean `true`.
      name:  "b.structuredFields.recordVersionMatches",
      flags: ["requireNextField"],
      call:  function (flag, value) {
        var opts = { nameIgnoresCase: true };
        opts[flag] = value;
        return b.structuredFields.recordVersionMatches("v=STSv1", "v", "STSv1", opts);
      },
    },
    {
      name:  "b.middleware.tracePropagate",
      flags: ["auditOnMissing"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.middleware.tracePropagate(opts);
      },
    },
    {
      name:  "b.middleware.protectedResourceMetadata",
      flags: ["dpopBoundAccessTokensRequired", "mtlsBoundAccessTokensRequired"],
      call:  function (flag, value) {
        var opts = {
          resource:             "https://api.example.com",
          authorizationServers: ["https://as.example.com"],
        };
        opts[flag] = value;
        return b.middleware.protectedResourceMetadata(opts);
      },
    },
    // The third spelling: a permission read TRUTHILY. `!!opts.allowProto` turned
    // the string "false" into true, so the off switch read as on. Measured before
    // the fix, on the prototype-pollution option itself: `allowProto: "false"`
    // and `"no"` both kept `__proto__` as an own key, exactly as `true` does.
    {
      name:  "b.safeJson.parse",
      flags: ["allowProto"],
      call:  function (flag, value) {
        var opts = { maxBytes: 4096 };
        opts[flag] = value;
        return b.safeJson.parse("{\"a\":1}", opts);
      },
    },
    {
      name:  "b.safeJson.stringify",
      flags: ["allowProto"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.safeJson.stringify({ a: 1 }, opts);
      },
    },
    {
      name:  "b.middleware.headers",
      flags: ["trustProxy"],
      call:  function (flag, value) {
        var opts = {};
        opts[flag] = value;
        return b.middleware.headers(opts);
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

// `cache.set`'s `seal` cannot ride the walk above: `seal: true` is refused on a
// memory backend, and this module gives every option error one code, so the
// boolean and the non-boolean answer with the same `cache/bad-opt` and the
// differential cannot tell them apart. Asserted directly instead, which is also
// the sharper claim: a value that is not a boolean is refused by name, where it
// used to be read as false and the value reached the backend unsealed.
async function testCacheSealRefusesAValueItCannotRead() {
  var cache = b.cache.create({ backend: "memory", namespace: "requirement-flags-seal" });

  var offThrew = null;
  try { await cache.set("k1", { v: 1 }, { seal: false }); } catch (e) { offThrew = e; }
  check("[setup] seal: false is accepted on a memory cache", offThrew === null,
        offThrew && String(offThrew.message).slice(0, 100));

  var absentThrew = null;
  try { await cache.set("k2", { v: 1 }, {}); } catch (e) { absentThrew = e; }
  check("[setup] omitting seal is accepted", absentThrew === null,
        absentThrew && String(absentThrew.message).slice(0, 100));

  var strings = ["true", "yes", "false", "no", 1, 0];
  var accepted = [];
  for (var i = 0; i < strings.length; i += 1) {
    var threw = null;
    try { await cache.set("k3", { v: 1 }, { seal: strings[i] }); } catch (e) { threw = e; }
    var namesTheOption = threw !== null && String(threw.message).indexOf("seal") !== -1;
    if (!namesTheOption) accepted.push(JSON.stringify(strings[i]));
  }
  check("cache.set refuses a seal that is not a boolean, naming the option" +
        (accepted.length ? " (accepted " + accepted.join(", ") + ")" : ""),
        accepted.length === 0);
}

// Two more that cannot ride the walk. `b.crypto.decrypt` throws a plain Error
// with no code either way, and `b.codepointClass.isForbiddenControlChar` is a
// per-codepoint predicate that throws nothing at all: it reads its options
// strictly instead, so a value that is not a boolean leaves the control
// character forbidden rather than permitting it.
async function testTwoReadsOutsideTheDifferential() {
  var msg = "";
  try { b.crypto.decrypt("bm90LWFuLWVudmVsb3Bl", {}, { allowLegacy: "true" }); }
  catch (e) { msg = String(e.message); }
  check("crypto.decrypt names allowLegacy when it is not a boolean",
        msg.indexOf("allowLegacy") !== -1, JSON.stringify(msg.slice(0, 90)));

  var LF = 0x0a;
  check("[setup] LF is forbidden by default",
        b.codepointClass.isForbiddenControlChar(LF) === true);
  check("[setup] allowLf: true permits LF",
        b.codepointClass.isForbiddenControlChar(LF, { allowLf: true }) === false);
  var leaked = [];
  ["true", "yes", 1, "1", "on"].forEach(function (v) {
    if (b.codepointClass.isForbiddenControlChar(LF, { allowLf: v }) === false) {
      leaked.push(JSON.stringify(v));
    }
  });
  check("a non-boolean allowLf does not permit LF" +
        (leaked.length ? " (permitted by " + leaked.join(", ") + ")" : ""),
        leaked.length === 0);

  // The sibling option in the same function reads the OTHER way, on purpose.
  // `forbidTab` imposes a restriction, so it is read truthily: a value that is
  // not a boolean leaves the tab forbidden. Reading it strictly, as the two
  // granting options above are read, turned `forbidTab: "true"` into "tabs
  // allowed" — the reverse of what the option is for. 78 tightening options
  // across lib/ are read truthily for this reason; the reading that is correct
  // follows from the direction, not from a preference for one shape.
  var TAB = 0x09;
  check("[setup] a tab is not a forbidden control character by default",
        b.codepointClass.isForbiddenControlChar(TAB) === false);
  check("[setup] forbidTab: true forbids the tab",
        b.codepointClass.isForbiddenControlChar(TAB, { forbidTab: true }) === true);
  var slipped = [];
  ["true", "yes", 1, "1"].forEach(function (v) {
    if (b.codepointClass.isForbiddenControlChar(TAB, { forbidTab: v }) !== true) {
      slipped.push(JSON.stringify(v));
    }
  });
  check("a truthy non-boolean forbidTab still forbids the tab" +
        (slipped.length ? " (allowed by " + slipped.join(", ") + ")" : ""),
        slipped.length === 0);
}

async function run() {
  try {
    await testARequirementFlagRefusesANonBoolean();
    await testCacheSealRefusesAValueItCannotRead();
    await testTwoReadsOutsideTheDifferential();
  } finally {
    if (_envDir !== null) {
      nodeFs.rmSync(_envDir, { recursive: true, force: true });
      _envDir = null;
    }
  }
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
