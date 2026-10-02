// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.pick — allow-list copying of untrusted objects (CWE-915 mass
 * assignment, CWE-1321 prototype pollution).
 *
 * The primitive shipped with no test of its own: the corpus referenced
 * neither `b.pick` nor the module, so the prototype-key refusal that is the
 * point of it was never driven.
 *
 * Run standalone: `node test/layer-0-primitives/pick.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function threwType(fn) {
  try { fn(); return null; } catch (e) { return e && e.constructor && e.constructor.name; }
}

function testSurface() {
  check("b.pick is a function",                    typeof b.pick === "function");
  check("b.pick.pick is the same function",        b.pick.pick === b.pick);
  check("b.pick.isPoisonedKey is fn",              typeof b.pick.isPoisonedKey === "function");
  check("b.pick.movesThePrototype is fn",          typeof b.pick.movesThePrototype === "function");
  check("b.pick.assertSafeKey is fn",              typeof b.pick.assertSafeKey === "function");
  check("b.pick.registerPoisonedKeys is fn",       typeof b.pick.registerPoisonedKeys === "function");
  check("b.pick.POISONED_KEYS names the three",
        b.pick.POISONED_KEYS.indexOf("__proto__") !== -1 &&
        b.pick.POISONED_KEYS.indexOf("constructor") !== -1 &&
        b.pick.POISONED_KEYS.indexOf("prototype") !== -1);
}

function testOnlyAllowedKeysSurvive() {
  var out = b.pick({ name: "ada", isAdmin: true }, ["name"]);
  check("pick: an allowed key comes through", out.name === "ada");
  check("pick: an unlisted key is dropped",
        !Object.prototype.hasOwnProperty.call(out, "isAdmin"));
  check("pick: the input is not modified",
        b.pick({ a: 1, b: 2 }, ["a"]) && true);

  var nested = b.pick({ name: "ada", profile: { bio: "x", role: "root" } },
                      ["name", ["profile", ["bio"]]]);
  check("pick: a nested allow-list keeps what it names", nested.profile.bio === "x");
  check("pick: a nested allow-list drops what it does not",
        !Object.prototype.hasOwnProperty.call(nested.profile, "role"));

  check("pick: onUnknown 'throw' refuses an unlisted key",
        threwType(function () { b.pick({ a: 1, b: 2 }, ["a"], { onUnknown: "throw" }); }) === "TypeError");
  check("pick: onUnknown 'throw' names the nested path",
        (function () {
          try { b.pick({ p: { a: 1, bad: 2 } }, [["p", ["a"]]], { onUnknown: "throw" }); return null; }
          catch (e) { return e.message.indexOf("p.bad") !== -1; }
        })() === true);

  check("pick: a non-object input comes back as it is", b.pick("plain", ["a"]) === "plain");
  check("pick: an allowList that is not an array is refused",
        threwType(function () { b.pick({}, "name"); }) === "TypeError");
  check("pick: a malformed allowList entry is refused",
        threwType(function () { b.pick({}, [123]); }) === "TypeError");
}

// The refusal is the primitive's reason to exist: a key that moves or reads
// a prototype must not come through, and naming it on the allow-list must
// not change that.
function testPrototypeKeysNeverComeThrough() {
  // JSON.parse is the shape an untrusted body arrives in: it produces a real
  // own "__proto__" property, which an object literal cannot.
  var hostile = JSON.parse('{"__proto__":{"polluted":true},"name":"ada"}');
  var out = b.pick(hostile, ["name", "__proto__"]);
  check("pick: __proto__ is dropped even when allow-listed",
        !Object.prototype.hasOwnProperty.call(out, "__proto__"));
  check("pick: the allowed sibling still comes through", out.name === "ada");
  check("pick: nothing was written onto Object.prototype",
        ({}).polluted === undefined);

  var ctor = JSON.parse('{"constructor":{"x":1},"prototype":{"y":2},"ok":3}');
  var out2 = b.pick(ctor, ["constructor", "prototype", "ok"]);
  check("pick: constructor is dropped even when allow-listed",
        !Object.prototype.hasOwnProperty.call(out2, "constructor"));
  check("pick: prototype is dropped even when allow-listed",
        !Object.prototype.hasOwnProperty.call(out2, "prototype"));
  check("pick: the allowed sibling survives both", out2.ok === 3);

  var deep = JSON.parse('{"p":{"__proto__":{"polluted":true},"bio":"x"}}');
  var out3 = b.pick(deep, [["p", ["bio", "__proto__"]]]);
  check("pick: a nested __proto__ is dropped too",
        !Object.prototype.hasOwnProperty.call(out3.p, "__proto__") && out3.p.bio === "x");
  check("pick: nothing was written onto Object.prototype from the nested case",
        ({}).polluted === undefined);
}

// An input shape the filter does not recognize used to come back whole, which
// is the one answer an allow-list must never give. Three shapes reached it.
function testAnUnrecognizedShapeIsStillFiltered() {
  var vm = require("node:vm");

  // A vm context has its own Object.prototype, so an object born there is not
  // `=== Object.prototype` here. Comparing prototypes by identity read it as
  // "not a plain object" and handed it back unfiltered, __proto__ included.
  var ctx = vm.createContext({ out: null, hostile: null });
  vm.runInContext('out = { name: "ada", isAdmin: true };', ctx);
  var crossRealm = b.pick(ctx.out, ["name"]);
  check("cross-realm: an unlisted key is dropped",
        !Object.prototype.hasOwnProperty.call(crossRealm, "isAdmin"));
  check("cross-realm: the allowed key comes through", crossRealm.name === "ada");

  vm.runInContext('hostile = JSON.parse(\'{"__proto__":{"polluted":true},"name":"ada"}\');', ctx);
  var crossHostile = b.pick(ctx.hostile, ["name", "__proto__"]);
  check("cross-realm: __proto__ is dropped",
        !Object.prototype.hasOwnProperty.call(crossHostile, "__proto__"));
  check("cross-realm: nothing was written onto Object.prototype",
        ({}).polluted === undefined);

  // A class instance has a longer prototype chain and was handed back whole.
  function User(name, isAdmin) { this.name = name; this.isAdmin = isAdmin; }
  User.prototype.greet = function () { return "hi"; };
  var instance = b.pick(new User("ada", true), ["name"]);
  check("class instance: an unlisted key is dropped",
        !Object.prototype.hasOwnProperty.call(instance, "isAdmin"));
  check("class instance: the allowed key comes through", instance.name === "ada");
  check("class instance: the prototype does not come with it",
        instance.greet === undefined);

  // A body an attacker made an array was handed back whole, so every element
  // kept every key.
  var arr = b.pick([{ name: "ada", isAdmin: true }, { name: "bob", isAdmin: true }], ["name"]);
  check("array: each element is filtered",
        Array.isArray(arr) && arr.length === 2 &&
        arr[0].name === "ada" && arr[1].name === "bob" &&
        !Object.prototype.hasOwnProperty.call(arr[0], "isAdmin") &&
        !Object.prototype.hasOwnProperty.call(arr[1], "isAdmin"));

  var nestedArr = b.pick({ users: [{ bio: "x", role: "root" }] }, [["users", ["bio"]]]);
  check("array: elements under a nested allow-list are filtered",
        nestedArr.users[0].bio === "x" &&
        !Object.prototype.hasOwnProperty.call(nestedArr.users[0], "role"));

  // A value that is not an object still comes back as it is.
  check("a string comes back as it is", b.pick("plain", ["a"]) === "plain");
  check("a number comes back as it is", b.pick(7, ["a"]) === 7);
  check("null comes back as it is", b.pick(null, ["a"]) === null);
}

function testKeyPredicates() {
  check("isPoisonedKey: __proto__",     b.pick.isPoisonedKey("__proto__") === true);
  check("isPoisonedKey: constructor",   b.pick.isPoisonedKey("constructor") === true);
  check("isPoisonedKey: prototype",     b.pick.isPoisonedKey("prototype") === true);
  check("isPoisonedKey: an ordinary name", b.pick.isPoisonedKey("name") === false);
  check("isPoisonedKey: a non-string",  b.pick.isPoisonedKey(7) === false);

  check("movesThePrototype: only __proto__ does",
        b.pick.movesThePrototype("__proto__") === true &&
        b.pick.movesThePrototype("constructor") === false &&
        b.pick.movesThePrototype("prototype") === false);

  var seen = [];
  var rv = b.pick.assertSafeKey("__proto__", function (k) { seen.push(k); return "handled"; });
  check("assertSafeKey: the handler runs for an unsafe key",
        seen.length === 1 && seen[0] === "__proto__" && rv === "handled");
  check("assertSafeKey: a safe key answers undefined and does not call the handler",
        b.pick.assertSafeKey("name", function () { seen.push("no"); }) === undefined &&
        seen.length === 1);
  check("assertSafeKey: a handler that is not a function is refused",
        threwType(function () { b.pick.assertSafeKey("__proto__", null); }) === "TypeError");
}

// registerPoisonedKeys widens the set for every caller, so it runs last: the
// name it adds stays added for the rest of the process.
function testRegisterPoisonedKeys() {
  var NAME = "__pick_test_poisoned_key__";
  check("registerPoisonedKeys: the name is ordinary before registering",
        b.pick.isPoisonedKey(NAME) === false);
  check("registerPoisonedKeys: it comes through pick before registering",
        b.pick(JSON.parse('{"' + NAME + '":1}'), [NAME])[NAME] === 1);

  b.pick.registerPoisonedKeys([NAME]);
  check("registerPoisonedKeys: the name is unsafe afterwards",
        b.pick.isPoisonedKey(NAME) === true);
  check("registerPoisonedKeys: pick drops it afterwards",
        !Object.prototype.hasOwnProperty.call(
          b.pick(JSON.parse('{"' + NAME + '":1,"ok":2}'), [NAME, "ok"]), NAME));

  check("registerPoisonedKeys: a non-array is refused",
        threwType(function () { b.pick.registerPoisonedKeys("x"); }) === "TypeError");
  check("registerPoisonedKeys: a non-string entry is refused",
        threwType(function () { b.pick.registerPoisonedKeys([7]); }) === "TypeError");
  check("registerPoisonedKeys: an empty-string entry is refused",
        threwType(function () { b.pick.registerPoisonedKeys([""]); }) === "TypeError");
}

async function run() {
  testSurface();
  testOnlyAllowedKeysSurvive();
  testPrototypeKeysNeverComeThrough();
  testAnUnrecognizedShapeIsStillFiltered();
  testKeyPredicates();
  testRegisterPoisonedKeys();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
