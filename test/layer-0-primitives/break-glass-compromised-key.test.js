// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.breakGlass.grant refuses a passkey second factor whose stored credential
 * key is compromised: anyone can sign that assertion, so it proves nothing
 * about the operator. The control grant differs only in the credential key.
 */

var helpers        = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var ck             = require("../helpers/compromised-keys");
var webauthn       = require("../helpers/webauthn");

var COMPROMISED = ck.ecKeyPair("prime256v1", 1n);
var CONTROL     = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "blamejs break-glass compromised-key control"));

function _fakeReq() {
  return {
    user:    { id: "user-test-1" },
    session: { id: "sess-test-1" },
    socket:  { remoteAddress: "127.0.0.1" },
    headers: { "user-agent": "test-agent" },
    method:  "POST",
    url:     "/admin/break-glass",
  };
}

async function testPasskeyFactorRefusesACompromisedCredentialKey() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bg-compromised-"));
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["passkey"] });
    var reg = helpers.registerCredential({ rpId: "example.test", keyPair: CONTROL });
    var enrolled = await b.auth.passkey.verifyRegistration({
      response: reg.response, expectedChallenge: reg.challenge,
      expectedOrigin: reg.origin, expectedRPID: reg.rpId,
    });
    check("break-glass compromised key: the helper's COSE key bytes are the bytes registration stores",
          webauthn.coseEc2PublicKey(CONTROL.publicKey)
            .equals(Buffer.from(enrolled.registrationInfo.credential.publicKey)));

    async function grantWith(pair) {
      var a = helpers.assertCredential(Object.assign({}, reg, { keyPair: pair }), { signCount: 1 });
      try {
        await b.breakGlass.grant({
          req: _fakeReq(), table: "patients",
          reason: "investigating ticket #12345 for compliance review",
          factor: {
            type: "passkey", response: a.response, expectedChallenge: a.challenge,
            expectedOrigin: reg.origin, expectedRPID: reg.rpId,
            credential: {
              id: enrolled.registrationInfo.credential.id,
              publicKey: webauthn.coseEc2PublicKey(pair.publicKey),
              counter: 0,
            },
          },
        });
        return "GRANTED";
      } catch (e) { return e.code || e.message; }
    }

    check("break-glass compromised key control: a passkey factor under an ordinary credential key grants",
          (await grantWith(CONTROL)) === "GRANTED");
    check("break-glass compromised key: a passkey factor under a credential key whose private key is 1 is refused",
          (await grantWith(COMPROMISED)) === "breakglass/bad-factor");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testPasskeyFactorRefusesACompromisedCredentialKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
