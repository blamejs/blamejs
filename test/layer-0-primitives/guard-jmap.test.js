// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("namespace",     typeof b.guardJmap === "object");
  check("validate fn",   typeof b.guardJmap.validate === "function");
  check("compliancePosture fn", typeof b.guardJmap.compliancePosture === "function");
  check("PROFILES",      typeof b.guardJmap.PROFILES === "object");
  check("error class",   typeof b.guardJmap.GuardJmapError === "function");
}

function testHappyPath() {
  var rv = b.guardJmap.validate({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  });
  check("returns using",         Array.isArray(rv.using));
  check("returns methodCalls",   Array.isArray(rv.methodCalls));
  check("createdIds normalized", rv.createdIds === null);
}

function testBadShapeRefused() {
  // RFC 8620 section 3.6.1 gives the request level four problem types:
  // a body that will not parse is notJSON, a parsed body that is not a
  // Request object is notRequest.
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label + " (" + (threw && threw.code) + ")",
      threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses non-object body",
    function () { b.guardJmap.validate("not-json"); },
    "urn:ietf:params:jmap:error:notJSON");
  expectThrow("refuses array body",
    function () { b.guardJmap.validate([]); },
    "urn:ietf:params:jmap:error:notRequest");
  expectThrow("refuses missing using",
    function () { b.guardJmap.validate({ methodCalls: [["x", {}, "c"]] }); },
    "urn:ietf:params:jmap:error:notRequest");
  expectThrow("refuses missing methodCalls",
    function () { b.guardJmap.validate({ using: [] }); },
    "urn:ietf:params:jmap:error:notRequest");
  expectThrow("refuses empty methodCalls",
    function () { b.guardJmap.validate({ using: [], methodCalls: [] }); },
    "urn:ietf:params:jmap:error:notRequest");
  expectThrow("refuses non-3-tuple call",
    function () { b.guardJmap.validate({ using: [], methodCalls: [["x", {}]] }); },
    "urn:ietf:params:jmap:error:notRequest");
  expectThrow("refuses non-string clientId",
    function () { b.guardJmap.validate({ using: [], methodCalls: [["x", {}, 5]] }); },
    "urn:ietf:params:jmap:error:notRequest");
}

function testUnknownCapabilityRefused() {
  var threw = null;
  try {
    b.guardJmap.validate({
      using:       ["urn:ietf:params:jmap:contacts"],
      methodCalls: [["Contact/get", {}, "c0"]],
    });
  } catch (e) { threw = e; }
  check("unknownCapability when not advertised",
    threw && threw.code === "urn:ietf:params:jmap:error:unknownCapability");

  var rv = b.guardJmap.validate({
    using:       ["urn:ietf:params:jmap:contacts"],
    methodCalls: [["Contact/get", {}, "c0"]],
  }, { serverCapabilities: { "urn:ietf:params:jmap:contacts": true } });
  check("unknownCapability cleared when advertised",
    rv.using.indexOf("urn:ietf:params:jmap:contacts") !== -1);
}

function testCapsTripped() {
  var threw = null;
  // Build a methodCalls with 33 entries (strict cap is 32)
  var calls = [];
  for (var i = 0; i < 33; i += 1) { calls.push(["x", {}, "c" + i]); }
  try { b.guardJmap.validate({ using: [], methodCalls: calls }); }
  catch (e) { threw = e; }
  // A limit refusal is the bare `limit` type plus a `limit` member naming
  // the cap, which is how RFC 8620 section 3.6.1 writes it.
  check("maxCallsInRequest tripped",
    threw && threw.code === "urn:ietf:params:jmap:error:limit" &&
    threw.limit === "maxCallsInRequest");

  // Oversize JSON body
  var big = "{\"using\":[],\"methodCalls\":[[\"x\",{}, \"c0\"]],\"pad\":\"" +
    "x".repeat(11000000) + "\"}";
  var threw2 = null;
  try { b.guardJmap.validate(big); } catch (e) { threw2 = e; }
  check("maxSizeRequest tripped",
    threw2 && threw2.code === "urn:ietf:params:jmap:error:limit" &&
    threw2.limit === "maxSizeRequest");
}

function testBackRefDepth() {
  // Build a deeply-nested back-reference shape with 9 `resultOf` keys
  // — strict cap is 8, so this trips.
  var node = { x: 1 };
  for (var i = 0; i < 9; i += 1) {
    node = { resultOf: node };
  }
  var threw = null;
  try {
    b.guardJmap.validate({
      using:       [],
      methodCalls: [["x", node, "c0"]],
    });
  } catch (e) { threw = e; }
  check("maxBackRefDepth tripped",
    threw && threw.code === "urn:ietf:params:jmap:error:limit" &&
    threw.limit === "maxBackRefDepth");
}

function testServerCapsNotMutated() {
  // Regression: pre-fix validate() injected `urn:ietf:params:jmap:core`
  // into the operator's `serverCapabilities` object in place; the
  // listener's shared object accumulated the boolean across requests
  // and broke the Session resource's RFC 8620 §2 capability shape.
  var caps = {
    "urn:ietf:params:jmap:mail":      { maxSizeMailboxName: 64 },
    "urn:ietf:params:jmap:submission": {},
  };
  var snapshot = JSON.stringify(caps);
  var body = '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"accountId":"A"},"c0"]]}';
  b.guardJmap.validate(body, { serverCapabilities: caps });
  check("guard-jmap does not mutate operator serverCapabilities",
    JSON.stringify(caps) === snapshot);
}

function testRequestSizeCapInBytesNotCodeUnits() {
  // Regression: pre-fix the size check counted UTF-16 code units;
  // post-fix counts UTF-8 bytes. Verify by passing a Buffer whose
  // byte length exceeds strict's 10 MiB cap — pre-fix this would
  // throw `<rawBody.length> bytes` (Buffer length is byte length
  // already, so both pre-fix and post-fix throw); the meaningful
  // test is the string path where UTF-16 vs UTF-8 differ.
  //
  // Construct a string that exceeds the strict 10 MiB byte cap
  // using all-emoji content; the JS string is 5 MiB UTF-16 code
  // units, the wire body is ~10 MiB UTF-8 bytes — pre-fix the
  // .length check let it pass.
  var emoji    = "😀";                                                                                // 4 UTF-8 bytes, 2 UTF-16 code units
  var fill     = emoji.repeat(2_700_000);                                                              // ~10.8 MiB UTF-8 bytes, 5.4 MiB code units
  var body = '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"_pad":"' + fill + '"},"c0"]]}';
  var threw = null;
  try {
    b.guardJmap.validate(body);                                                                      // strict default — 10 MiB cap
  } catch (e) { threw = e; }
  check("guard-jmap size cap measured in UTF-8 bytes (not code units)",
    threw && /bytes exceeds cap/.test(threw.message));
}

function testTheCapBoundsTheBodyTheHandlersActuallyGet() {
  // The cap exists to bound the data the handlers walk, and `validate` used
  // to return the object it was given. Measuring one object and handing on
  // another bounds nothing: every way a value can answer a second read
  // differently is a way past the cap. So the body the caller receives IS
  // the JSON form that was measured, read once, and each shape below is
  // answered by what that one reading produced rather than by a refusal
  // list that has to name it first.
  var pad = "x".repeat(11 * 1024 * 1024);

  // A `toJSON` hook: the form is `{}`, so `{}` is what the handler gets.
  var served = b.guardJmap.validate({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { _pad: pad, toJSON: function () { return {}; } }, "c0"]],
  });
  check("a body behind a toJSON hook reaches the handler as its JSON form",
        JSON.stringify(served.methodCalls[0][1]) === "{}",
        JSON.stringify(served.methodCalls[0][1]).slice(0, 80));

  // An inherited hook is the same hook.
  function Carrier() { this._pad = pad; }
  Carrier.prototype.toJSON = function () { return {}; };
  var inheritedServed = b.guardJmap.validate({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", new Carrier(), "c0"]],
  });
  check("and so does one behind an inherited hook",
        JSON.stringify(inheritedServed.methodCalls[0][1]) === "{}",
        JSON.stringify(inheritedServed.methodCalls[0][1]).slice(0, 80));

  // A boxed primitive serializes as its primitive, so the properties hung
  // on it are not in what the handler receives; what is left is a string
  // where RFC 8620 §3.2 wants an arguments object, and the request is
  // refused on that, with the 11 MiB never in play.
  var threwBoxed = null;
  try {
    b.guardJmap.validate({
      using:       ["urn:ietf:params:jmap:core"],
      methodCalls: [["Core/echo", Object.assign(new String(""), { _pad: pad }), "c0"]],
    });
  } catch (e) { threwBoxed = e; }
  check("a boxed primitive arrives as the primitive it writes, and is refused for it",
        threwBoxed && threwBoxed.code === "urn:ietf:params:jmap:error:notRequest" &&
        threwBoxed.message.indexOf("must be an object") !== -1,
        JSON.stringify({ code: threwBoxed && threwBoxed.code }));

  // An accessor, at an object key and at an array index: read once, and the
  // second answer reaches nobody.
  var reads = 0;
  var live = { using: ["urn:ietf:params:jmap:core"] };
  Object.defineProperty(live, "methodCalls", {
    enumerable: true,
    get: function () {
      reads += 1;
      if (reads === 1) return [["Core/echo", {}, "c0"]];
      var many = [];
      for (var n = 0; n < 10000; n += 1) many.push(["Core/echo", { _pad: pad }, "c" + n]);
      return many;
    },
  });
  var liveServed = b.guardJmap.validate(live);
  check("a getter is read once and the handler gets that reading",
        reads === 1 && liveServed.methodCalls.length === 1,
        JSON.stringify({ reads: reads, calls: liveServed.methodCalls.length }));

  var indexReads = 0;
  var calls = [];
  Object.defineProperty(calls, "0", {
    enumerable: true, configurable: true,
    get: function () {
      indexReads += 1;
      return indexReads === 1
        ? ["Core/echo", {}, "c0"]
        : ["Core/echo", { _pad: pad }, "c0"];
    },
  });
  var indexServed = b.guardJmap.validate({
    using: ["urn:ietf:params:jmap:core"], methodCalls: calls,
  });
  check("an accessor at an array index is answered the same way",
        indexReads === 1 && JSON.stringify(indexServed.methodCalls[0][1]) === "{}",
        JSON.stringify({ reads: indexReads, arg: indexServed.methodCalls[0][1] }));

  // A form genuinely over the cap is still refused, and named.
  var threwBig = null;
  try {
    b.guardJmap.validate({
      using:       ["urn:ietf:params:jmap:core"],
      methodCalls: [["Core/echo", { _pad: pad }, "c0"]],
    });
  } catch (e) { threwBig = e; }
  check("a body whose JSON form is over the cap is refused",
        threwBig && threwBig.code === "urn:ietf:params:jmap:error:limit",
        JSON.stringify({ code: threwBig && threwBig.code }));
  check("and the refusal names maxSizeRequest",
        threwBig && threwBig.limit === "maxSizeRequest");

  // And a body under the cap still validates, hook or no hook.
  var small = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1, toJSON: function () { return { hi: 1 }; } }, "c0"]],
  };
  check("a small body carrying a hook is not refused",
        b.guardJmap.validate(small).methodCalls.length === 1);
}

function testTheKeysTheListenerJudgesReachItWhicheverWayTheBodyArrives() {
  // `b.mailServer.jmap` refuses an argument named `__proto__` by name and
  // admits `constructor`, `prototype` and the rest as the ordinary names
  // RFC 8620 section 1.2 and RFC 8621 section 4.1.1 make them. It can only do
  // either if the key is still there when it looks. Deleting the key on the
  // way through answers the request with a member missing and tells the
  // client it succeeded, which is weaker than the refusal, and it made the
  // two input forms disagree: a body that arrived as text was stripped and
  // served while the same body pre-parsed was refused.
  var TEXT = '{"using":["urn:ietf:params:jmap:core"],"methodCalls":' +
    '[["Core/echo",{"accountId":"A1","constructor":"c","prototype":"p"},"c0"]],' +
    '"createdIds":{"constructor":"M1"}}';
  ["text", "pre-parsed"].forEach(function (form) {
    var out = b.guardJmap.validate(form === "text" ? TEXT : JSON.parse(TEXT));
    var args = out.methodCalls[0][1];
    check("keeps the names that are legal, as own properties (" + form + ")",
          args.constructor === "c" && args.prototype === "p" && args.accountId === "A1",
          JSON.stringify(Object.keys(args)));
    check("and a creation id named constructor survives (" + form + ")",
          out.createdIds.constructor === "M1", JSON.stringify(out.createdIds));
    check("while the arguments object itself carries no foreign prototype (" + form + ")",
          Object.getPrototypeOf(args) === Object.prototype &&
          Object.getPrototypeOf(out) === Object.prototype &&
          ({}).accountId === undefined,
          JSON.stringify(Object.getPrototypeOf(args)));
  });

  // Admitting the names a protocol uses is not admitting the one that moves a
  // prototype. `__proto__` has no use as a JMAP name, and `validate` handing
  // it back as an own key puts the request author in control of whatever the
  // caller merges the result into: RFC 8620 section 5.3 tells an operator to
  // merge `createdIds` into their own map, and a merge is an assignment. It is
  // refused wherever it appears, in either input form.
  [
    ["a method-call argument", '{"using":["urn:ietf:params:jmap:core"],"methodCalls":' +
      '[["Core/echo",{"__proto__":{"polluted":true},"ok":1},"c0"]]}'],
    ["a nested argument", '{"using":["urn:ietf:params:jmap:core"],"methodCalls":' +
      '[["Core/echo",{"a":{"b":[{"__proto__":{"polluted":true}}]}},"c0"]]}'],
    ["a creation id", '{"using":["urn:ietf:params:jmap:core"],"methodCalls":' +
      '[["Core/echo",{"ok":1},"c0"]],"createdIds":{"__proto__":"M1","k1":"M2"}}'],
  ].forEach(function (c) {
    ["text", "pre-parsed"].forEach(function (form) {
      var threw = null;
      try { b.guardJmap.validate(form === "text" ? c[1] : JSON.parse(c[1])); }
      catch (e) { threw = e; }
      check("refused: " + c[0] + " naming the prototype setter (" + form + ")",
            threw !== null && threw.code === "urn:ietf:params:jmap:error:notRequest",
            JSON.stringify({ code: threw && threw.code, message: threw && threw.message }));
    });
  });
  check("and nothing was polluted by the attempt", ({}).polluted === undefined);
  var legalIds = b.guardJmap.validate(JSON.parse(
    '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{},"c0"]],' +
    '"createdIds":{"constructor":"M1","prototype":"M2","k1":"M3"}}'));
  check("and the creation ids that name no prototype setter are served",
        legalIds.createdIds.constructor === "M1" && legalIds.createdIds.prototype === "M2" &&
        legalIds.createdIds.k1 === "M3", JSON.stringify(legalIds.createdIds));

  // How many members one object may carry is a safeJson setting, not a JMAP
  // one, and the two branches took different defaults for it: 10,000 on the
  // text path and a million on the pre-parsed one. RFC 8620 section 5.3 puts
  // no bound on `createdIds`, and the listener reads a body over HTTP as an
  // object and over WebSocket as text, so the same client was served on one
  // transport and refused on the other, for a body inside every cap the
  // session advertises.
  var manyIds = { using: ["urn:ietf:params:jmap:core"],
                  methodCalls: [["Core/echo", {}, "c0"]], createdIds: {} };
  for (var n = 0; n < 20000; n += 1) manyIds.createdIds["k" + n] = "M" + n;                           // allow:raw-byte-literal — test-only member count
  var manyText = JSON.stringify(manyIds);
  ["text", "pre-parsed"].forEach(function (form) {
    var out = null;
    try { out = b.guardJmap.validate(form === "text" ? manyText : manyIds); }
    catch (e) { out = e; }
    check("a wide createdIds map reads the same whichever form arrives (" + form + ")",
          out !== null && !(out instanceof Error) &&
          Object.keys(out.createdIds).length === 20000,                                               // allow:raw-byte-literal — test-only member count
          JSON.stringify({ code: out && out.code, bytes: manyText.length }));
  });

  // Past that bound the body is still valid JSON and still inside
  // `maxSizeRequest`, so `notJSON` describes neither what arrived nor why it
  // was refused; RFC 8620 section 3.6.1 keeps that type for a body that did
  // not parse. The bound is not a limit the session advertises, so the
  // refusal is `notRequest` and the message names it.
  var tooWide = { using: ["urn:ietf:params:jmap:core"],
                  methodCalls: [["Core/echo", {}, "c0"]], createdIds: {} };
  for (var w = 0; w <= b.guardJmap.MAX_KEYS_PER_OBJECT; w += 1) tooWide.createdIds["k" + w] = "M";
  var tooWideText = JSON.stringify(tooWide);
  ["text", "pre-parsed"].forEach(function (form) {
    var threwWide = null;
    try { b.guardJmap.validate(form === "text" ? tooWideText : tooWide); }
    catch (e) { threwWide = e; }
    check("an object past MAX_KEYS_PER_OBJECT is refused as notRequest (" + form + ")",
          threwWide !== null &&
          threwWide.code === "urn:ietf:params:jmap:error:notRequest" &&
          threwWide.message.indexOf(String(b.guardJmap.MAX_KEYS_PER_OBJECT)) !== -1,
          JSON.stringify({ code: threwWide && threwWide.code,
                           message: threwWide && threwWide.message }));
  });

  // Same reasoning for nesting: a body deeper than the parser reads is not
  // malformed JSON either.
  var deep = { using: ["urn:ietf:params:jmap:core"],
               methodCalls: [["Core/echo", {}, "c0"]], createdIds: {} };
  var cursor = deep.methodCalls[0][1];
  for (var d = 0; d < 200; d += 1) { cursor.next = {}; cursor = cursor.next; }                        // allow:raw-byte-literal — test-only nesting depth
  var deepText = JSON.stringify(deep);
  ["text", "pre-parsed"].forEach(function (form) {
    var threwDeep = null;
    try { b.guardJmap.validate(form === "text" ? deepText : deep); }
    catch (e) { threwDeep = e; }
    check("a body nested past what the parser reads is refused as notRequest (" + form + ")",
          threwDeep !== null && threwDeep.code === "urn:ietf:params:jmap:error:notRequest",
          JSON.stringify({ code: threwDeep && threwDeep.code,
                           message: threwDeep && threwDeep.message }));
  });
}

function testEveryProfileSizeCapIsOneTheParserWillHonor() {
  // `maxSizeRequest` is published to clients in the session's
  // urn:ietf:params:jmap:core capability (RFC 8620 section 2), so it is a
  // promise about what the server accepts. A string body goes through
  // `safeJson.parse`, which refuses anything over its own 64 MiB ceiling
  // whatever the caller asks for, so a profile declaring more than that
  // publishes a number no branch honors. Measured before this bound: a
  // 66 MiB body under the permissive profile's declared 100 MiB came back
  // as notJSON, "body is not valid JSON", rather than as a size refusal.
  var ceiling = b.safeJson.ABSOLUTE_MAX_BYTES;
  Object.keys(b.guardJmap.PROFILES).forEach(function (name) {
    var declared = b.guardJmap.PROFILES[name].maxSizeRequest;
    check("profile '" + name + "' declares a maxSizeRequest the parser honors",
          declared <= ceiling,
          JSON.stringify({ declared: declared, ceiling: ceiling }));
  });
}

function testRequestSizeCapAppliesToAPreParsedBody() {
  // `validate` documents a pre-parsed object as an accepted input, and
  // b.mail.server.jmap's apiHandler reads `req.body`, which is what
  // b.middleware.bodyParser leaves behind. The size cap has to hold on
  // that input too: measuring only the string form left the documented
  // wiring with maxSizeRequest unenforced.
  var pad  = "x".repeat(11 * 1024 * 1024);                                                             // 11 MiB > strict's 10 MiB cap
  var body = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { _pad: pad }, "c0"]],
  };
  var threw = null;
  try { b.guardJmap.validate(body); } catch (e) { threw = e; }
  check("pre-parsed body over maxSizeRequest refused",
    threw && threw.code === "urn:ietf:params:jmap:error:limit");
  check("pre-parsed size refusal names maxSizeRequest",
    threw && threw.limit === "maxSizeRequest");

  var small = {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  };
  check("a pre-parsed body under the cap still validates",
    b.guardJmap.validate(small).methodCalls.length === 1);
}

function testCompliancePosture() {
  check("posture: hipaa → strict",   b.guardJmap.compliancePosture("hipaa") === "strict");
  check("posture: pci-dss → strict", b.guardJmap.compliancePosture("pci-dss") === "strict");
  check("posture: gdpr → strict",    b.guardJmap.compliancePosture("gdpr") === "strict");
  check("posture: soc2 → strict",    b.guardJmap.compliancePosture("soc2") === "strict");
  check("posture: unknown → null",   b.guardJmap.compliancePosture("nope") === null);
}

function testCapabilityPrototypeKeyBypass() {
  // A `using` capability whose name is a JS prototype-key (constructor /
  // __proto__ / toString / ...) is NOT advertised by the server and MUST
  // be refused as unknownCapability. Pre-fix the allowlist test read
  // `serverCaps[cap]` by bracket access, so an inherited Object.prototype
  // member resolved truthy and the attacker-supplied bogus capability
  // passed the gate — a fail-open in the RFC 8620 §3.6.1 capability
  // allowlist driven entirely by the request body.
  var protoKeys = ["constructor", "__proto__", "toString", "valueOf",
    "hasOwnProperty", "isPrototypeOf", "toLocaleString", "propertyIsEnumerable"];
  for (var i = 0; i < protoKeys.length; i += 1) {
    var threw = null;
    try {
      b.guardJmap.validate({
        using:       [protoKeys[i]],
        methodCalls: [["Core/echo", {}, "c0"]],
      }, { serverCapabilities: { "urn:ietf:params:jmap:mail": true } });
    } catch (e) { threw = e; }
    check("prototype-key capability '" + protoKeys[i] + "' refused as unknownCapability",
      threw && threw.code === "urn:ietf:params:jmap:error:unknownCapability");
  }
  // An operator that explicitly disables a capability (own key, falsy
  // value) still refuses it — presence alone is not advertisement.
  var threwDisabled = null;
  try {
    b.guardJmap.validate({
      using:       ["urn:ietf:params:jmap:mail"],
      methodCalls: [["Mailbox/get", {}, "c0"]],
    }, { serverCapabilities: { "urn:ietf:params:jmap:mail": false } });
  } catch (e) { threwDisabled = e; }
  check("explicitly-disabled capability (own key, falsy) refused",
    threwDisabled && threwDisabled.code === "urn:ietf:params:jmap:error:unknownCapability");
}

function testProfilePrototypeKeyRefused() {
  // A profile / posture name that collides with a JS prototype-key must
  // resolve to bad-profile, never silently disable the request caps
  // (PROFILES["constructor"] would otherwise be the inherited Object
  // function — truthy — so `if (!caps)` never fired and every size /
  // count cap was bypassed).
  ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty"].forEach(function (k) {
    var threw = null;
    try { b.guardJmap.validate({ using: [], methodCalls: [["x", {}, "c0"]] }, { profile: k }); }
    catch (e) { threw = e; }
    check("profile '" + k + "' refused as bad-profile",
      threw && threw.code === "guard-jmap/bad-profile");
  });
}

function run() {
  testSurface();
  testHappyPath();
  testBadShapeRefused();
  testUnknownCapabilityRefused();
  testCapabilityPrototypeKeyBypass();
  testProfilePrototypeKeyRefused();
  testCapsTripped();
  testBackRefDepth();
  testServerCapsNotMutated();
  testRequestSizeCapInBytesNotCodeUnits();
  testEveryProfileSizeCapIsOneTheParserWillHonor();
  testTheCapBoundsTheBodyTheHandlersActuallyGet();
  testTheKeysTheListenerJudgesReachItWhicheverWayTheBodyArrives();
  testRequestSizeCapAppliesToAPreParsedBody();
  testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-jmap] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
