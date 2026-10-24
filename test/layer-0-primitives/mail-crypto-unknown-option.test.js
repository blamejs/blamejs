// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every b.mail.crypto.pgp and b.mail.crypto.smime primitive refuses an option
 * it does not accept with its module's bad-opts code, the code its operator
 * docs name for a malformed `opts`. The control passes the same call without
 * the unknown key and gets a coded refusal, thrown or returned, for its
 * missing or malformed input.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var pgp   = b.mail.crypto.pgp;
var smime = b.mail.crypto.smime;

function _code(fn) {
  try { fn(); return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("uncoded " + (e && e.constructor && e.constructor.name) + ": " + (e && e.message)); }
}

var CASES = [
  { name: "pgp.sign", code: "mail-crypto/pgp/bad-opts", call: function (o) { return pgp.sign(o); },
    opts: { message: "x", privateKeyPem: "not a key" } },
  { name: "pgp.verify", code: "mail-crypto/pgp/bad-opts", call: function (o) { return pgp.verify(o); },
    opts: { message: "x", armored: "a", publicKeyPem: "k" } },
  { name: "pgp.experimental.encrypt", code: "mail-crypto/pgp/bad-opts",
    call: function (o) { return pgp.experimental.encrypt(o); }, opts: { message: "x", recipients: [] } },
  { name: "pgp.experimental.decrypt", code: "mail-crypto/pgp/bad-opts",
    call: function (o) { return pgp.experimental.decrypt(o); }, opts: { armored: "a" } },
  { name: "smime.sign", code: "mail-crypto/smime/bad-opts", call: function (o) { return smime.sign(o); },
    opts: { message: "x" } },
  { name: "smime.verify", code: "mail-crypto/smime/bad-opts", call: function (o) { return smime.verify(o); },
    opts: { message: "x" } },
  { name: "smime.verifyAll", code: "mail-crypto/smime/bad-opts", call: function (o) { return smime.verifyAll(o); },
    opts: { message: "x" } },
  { name: "smime.checkCert", code: "mail-crypto/smime/bad-opts", call: function (o) { return smime.checkCert(o); },
    opts: { certPem: "not a certificate" } },
];

function testAnUnknownOptionCarriesTheModuleBadOptsCode() {
  CASES.forEach(function (c) {
    var control = _code(function () { c.call(Object.assign({}, c.opts)); });
    check("mail-crypto unknown option control: " + c.name + " without the unknown key returns or raises a coded refusal",
          control.indexOf("uncoded") !== 0, control);
    var withUnknown = _code(function () { c.call(Object.assign({ bogusOption: 1 }, c.opts)); });
    check("mail-crypto unknown option: " + c.name + " refuses an unknown option with " + c.code,
          withUnknown === c.code, withUnknown);
  });
}

function testSmimeVerifyRefusesAnEmptyMessage() {
  var code = _code(function () { smime.verify({ message: "", signature: Buffer.alloc(1), signerPublicKey: new Uint8Array(1) }); });
  check("smime.verify: an empty message is refused with mail-crypto/smime/bad-opts",
        code === "mail-crypto/smime/bad-opts", code);
}

async function run() {
  testAnUnknownOptionCarriesTheModuleBadOptsCode();
  testSmimeVerifyRefusesAnEmptyMessage();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
