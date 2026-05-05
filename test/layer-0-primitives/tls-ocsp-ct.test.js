"use strict";
/**
 * b.network.tls.ocsp + b.network.tls.ct — surface tests.
 *
 * The protocol-side OCSP request/response and SCT signature
 * verification are deferred (need ASN.1 parsing). What ships here is
 * the operator surface — connect/requireGood wrappers + cert
 * inspection + requireScts predicate factory. Live-network tests are
 * gated behind operator-supplied integration runs.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testOcspSurface() {
  check("network.tls.ocsp.connect is a function",
        typeof b.network.tls.ocsp.connect === "function");
  check("network.tls.ocsp.requireStapled is a function",
        typeof b.network.tls.ocsp.requireStapled === "function");
}

function testCtSurface() {
  check("network.tls.ct.inspect is a function",
        typeof b.network.tls.ct.inspect === "function");
  check("network.tls.ct.requireScts is a function",
        typeof b.network.tls.ct.requireScts === "function");
  check("network.tls.ct.APPROVED_LOGS is a frozen array",
        Array.isArray(b.network.tls.ct.APPROVED_LOGS) &&
        Object.isFrozen(b.network.tls.ct.APPROVED_LOGS));
}

function testCtInspectRejectsNonBuffer() {
  var threw = null;
  try { b.network.tls.ct.inspect("not a buffer"); }
  catch (e) { threw = e; }
  check("ct.inspect rejects non-Buffer",
        threw && /ct-bad-input/.test(threw.code || ""));
}

function testCtInspectFakeCertNoExtension() {
  // A buffer that doesn't contain the SCT OID bytes.
  var fake = Buffer.from("not a real cert", "utf8");
  var rv = b.network.tls.ct.inspect(fake);
  check("ct.inspect on non-SCT cert → hasSctExtension = false",
        rv.hasSctExtension === false);
}

function testCtInspectFakeCertWithOid() {
  // Embed the SCT OID bytes inside an arbitrary buffer.
  var oid = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  var fake = Buffer.concat([Buffer.alloc(50), oid, Buffer.alloc(50)]);
  var rv = b.network.tls.ct.inspect(fake);
  check("ct.inspect on cert with SCT OID → hasSctExtension = true",
        rv.hasSctExtension === true);
}

function testRequireSctsPredicate() {
  var pred = b.network.tls.ct.requireScts({ minScts: 2 });
  check("requireScts returns a function",
        typeof pred === "function");
  // Missing cert → error.
  var err1 = pred(null);
  check("requireScts(null) → ct-no-cert error",
        err1 && /ct-no-cert/.test(err1.code || ""));
  // Cert with no SCT OID → error.
  var noScts = { raw: Buffer.from("nope") };
  var err2 = pred(noScts);
  check("requireScts(non-SCT cert) → ct-no-sct-extension error",
        err2 && /ct-no-sct-extension/.test(err2.code || ""));
  // Cert with SCT OID → null (no error).
  var oid = Buffer.from([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  var withScts = { raw: Buffer.concat([Buffer.alloc(20), oid]) };
  var err3 = pred(withScts);
  check("requireScts(cert with SCT) → null (passes)",
        err3 === null);
}

async function run() {
  testOcspSurface();
  testCtSurface();
  testCtInspectRejectsNonBuffer();
  testCtInspectFakeCertNoExtension();
  testCtInspectFakeCertWithOid();
  testRequireSctsPredicate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
