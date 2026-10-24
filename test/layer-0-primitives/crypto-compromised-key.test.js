// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.compromisedKey / b.crypto.assertNotCompromised: a key anyone can
 * hold the private half of is reported, in every form a key arrives in.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeCrypto = require("node:crypto");
var asn1       = require("../../lib/asn1-der");
var pki        = require("../../lib/vendor/blamejs-pki.cjs");
var ck         = require("../helpers/compromised-keys");
var crafted    = require("../helpers/crafted-compromised-certs");
var composite  = require("../helpers/composite-key-cert");

function _id(key) {
  var f = b.crypto.compromisedKey(key);
  return f === null ? null : f.id;
}
function _code(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.message; }
}
function _x(pub) { return pub.export({ format: "jwk" }).x; }

function testCurveOrdersAreRight() {
  Object.keys(ck.CURVES).forEach(function (curve) {
    var n = ck.CURVES[curve][2];
    check("compromised key fixtures: (n - 1)G and G share an x coordinate on " + curve,
          _x(ck.ecKeyPair(curve, n - 1n).publicKey) === _x(ck.ecKeyPair(curve, 1n).publicKey));
  });
}

function testSmallScalarBoundaries() {
  Object.keys(ck.CURVES).forEach(function (curve) {
    var n = ck.CURVES[curve][2];
    [1n, 2n, 255n, n - 1n, n - 255n].forEach(function (d) {
      check("compromisedKey: " + curve + " scalar " + (d < 256n ? d : "n - " + (n - d)) + " is small-ec-scalar",
            _id(ck.ecKeyPair(curve, d).publicKey) === "small-ec-scalar");
    });
    [256n, n - 256n, ck.labelScalar(curve, "compromised-key test")].forEach(function (d) {
      check("compromisedKey: " + curve + " scalar " + (d === 256n ? "256" : d === n - 256n ? "n - 256" : "label") +
            " is not compromised",
            _id(ck.ecKeyPair(curve, d).publicKey) === null);
    });
  });
}

async function testEveryKeyFormAgrees() {
  var bad = ck.ecKeyPair("secp384r1", 1n);
  var good = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "control"));
  var subtle = nodeCrypto.webcrypto.subtle;
  function forms(pair) {
    var spki = pair.publicKey.export({ type: "spki", format: "der" });
    return [
      ["public KeyObject", pair.publicKey],
      ["private KeyObject", pair.privateKey],
      ["public JWK", pair.publicKey.export({ format: "jwk" })],
      ["SPKI PEM", pair.publicKey.export({ type: "spki", format: "pem" })],
      ["SPKI DER", spki],
      ["PKCS#8 PEM", pair.privateKey.export({ type: "pkcs8", format: "pem" })],
    ];
  }
  forms(bad).forEach(function (f) {
    check("compromisedKey: scalar 1 as " + f[0] + " is small-ec-scalar", _id(f[1]) === "small-ec-scalar");
  });
  forms(good).forEach(function (f) {
    check("compromisedKey control: an ordinary key as " + f[0] + " is not compromised", _id(f[1]) === null);
  });
  var cryptoKey = await subtle.importKey("spki", bad.publicKey.export({ type: "spki", format: "der" }),
    { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]);
  check("compromisedKey: scalar 1 as a WebCrypto CryptoKey is small-ec-scalar", _id(cryptoKey) === "small-ec-scalar");

  var certDer = ck.P384_COMPROMISED_CA_DER;
  [["certificate DER", certDer], ["certificate PEM", ck.certPem(certDer)],
   ["X509Certificate", new nodeCrypto.X509Certificate(certDer)]].forEach(function (f) {
    check("compromisedKey: a certificate for scalar 1 as " + f[0] + " is small-ec-scalar",
          _id(f[1]) === "small-ec-scalar");
  });
  check("compromisedKey control: the control certificate is not compromised",
        _id(ck.certPem(ck.P384_CONTROL_CA_DER)) === null);
}

function _rsaPssSpki(rsaPublicKey) {
  var spki = rsaPublicKey.export({ type: "spki", format: "der" });
  var kids = asn1.readSequence(asn1.readNode(spki, 0).value);
  var rsaPub = asn1.readBitString(kids[1]);
  return asn1.writeSequence([
    asn1.writeSequence([asn1.writeOid("1.2.840.113549.1.1.10")]),
    asn1.writeBitString(rsaPub, 0),
  ]);
}

function testListedKeyInEveryEncoding() {
  var cert = new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM);
  var pss = nodeCrypto.createPublicKey({ key: _rsaPssSpki(cert.publicKey), format: "der", type: "spki" });
  check("compromised key fixtures: the re-encoded eDellRoot key loads as rsa-pss",
        pss.asymmetricKeyType === "rsa-pss");
  [["certificate PEM", ck.EDELLROOT_CERT_PEM], ["X509Certificate", cert],
   ["public KeyObject", cert.publicKey], ["public JWK", cert.publicKey.export({ format: "jwk" })],
   ["SPKI DER", cert.publicKey.export({ type: "spki", format: "der" })],
   ["RSASSA-PSS SPKI", pss]].forEach(function (f) {
    var found = b.crypto.compromisedKey(f[1]);
    check("compromisedKey: the eDellRoot key as " + f[0] + " is listed",
          found !== null && found.id === "listed" && /eDellRoot/.test(found.reason), JSON.stringify(found));
  });
}

function testAgreesWithPkiLint() {
  [ck.P256_COMPROMISED_CA_DER, ck.P256_CONTROL_CA_DER, ck.P256_COMPROMISED_LEAF_DER,
   ck.P384_COMPROMISED_CA_DER, ck.P384_CONTROL_CA_DER,
   Buffer.from(new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).raw)].forEach(function (der, i) {
    var lint = pki.lint.certificate(der, { profile: "key-compromise" });
    var pkiSays = lint.findings.some(function (f) { return /^lint\/key-compromise\//.test(f.id); });
    var certSays = b.crypto.compromisedKey(der) !== null;
    var keySays = b.crypto.compromisedKey(new nodeCrypto.X509Certificate(der).publicKey) !== null;
    check("compromisedKey: certificate " + i + " agrees with pki.lint as a certificate and as a bare key",
          pkiSays === certSays && certSays === keySays, JSON.stringify({ pkiSays, certSays, keySays }));
  });
}

function testOrdinaryKeysOfEveryType() {
  [["rsa", { modulusLength: 2048 }], ["ed25519", {}], ["ed448", {}], ["x25519", {}],
   ["ec", { namedCurve: "P-256" }], ["ec", { namedCurve: "P-521" }], ["ec", { namedCurve: "secp256k1" }],
   ["ml-dsa-87", {}], ["ml-kem-1024", {}]].forEach(function (spec) {
    var pair = nodeCrypto.generateKeyPairSync(spec[0], spec[1]);
    check("compromisedKey: a fresh " + spec[0] + (spec[1].namedCurve ? " " + spec[1].namedCurve : "") +
          " key is not compromised", _id(pair.publicKey) === null);
  });
}

function testUnreadableInputThrows() {
  [["a string that is not a key", "not a key"], ["a number", 42], ["an empty object", {}],
   ["null", null], ["a secret key", nodeCrypto.createSecretKey(Buffer.alloc(32, 7))],
   ["random bytes", nodeCrypto.randomBytes(64)]].forEach(function (f) {
    check("compromisedKey: " + f[0] + " throws crypto/bad-key",
          _code(function () { b.crypto.compromisedKey(f[1]); }) === "crypto/bad-key");
  });
}

function testAssertNotCompromised() {
  var good = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "assert")).publicKey;
  check("assertNotCompromised: returns an ordinary key", b.crypto.assertNotCompromised(good) === good);
  var bad = ck.ecKeyPair("prime256v1", 1n).publicKey;
  check("assertNotCompromised: throws crypto/compromised-key by default",
        _code(function () { b.crypto.assertNotCompromised(bad); }) === "crypto/compromised-key");
  function ModError(code, message) { this.code = code; this.message = message; }
  var thrown = null;
  try { b.crypto.assertNotCompromised(bad, { errorClass: ModError, code: "mod/compromised-key", label: "issuer key" }); }
  catch (e) { thrown = e; }
  check("assertNotCompromised: throws the caller's error class, code and label",
        thrown instanceof ModError && thrown.code === "mod/compromised-key" && /^issuer key /.test(thrown.message),
        thrown && thrown.message);
}

function testVerifyRefusesACompromisedKey() {
  var data = Buffer.from("payload", "utf8");
  [["prime256v1", 1n], ["secp384r1", 1n]].forEach(function (spec) {
    var bad = ck.ecKeyPair(spec[0], spec[1]);
    var good = ck.ecKeyPair(spec[0], ck.labelScalar(spec[0], "verify control"));
    var badSig = nodeCrypto.sign(null, data, bad.privateKey);
    var goodSig = nodeCrypto.sign(null, data, good.privateKey);
    check("crypto.verify control: an ordinary " + spec[0] + " signature verifies",
          b.crypto.verify(data, goodSig, good.publicKey) === true &&
          b.crypto.verify(data, goodSig, good.publicKey.export({ type: "spki", format: "pem" })) === true);
    check("crypto.verify fixture: node accepts the scalar-1 " + spec[0] + " signature",
          nodeCrypto.verify(null, data, bad.publicKey, badSig) === true);
    check("crypto.verify: a valid signature by a scalar-1 " + spec[0] + " key does not verify",
          b.crypto.verify(data, badSig, bad.publicKey) === false &&
          b.crypto.verify(data, badSig, bad.publicKey.export({ type: "spki", format: "pem" })) === false);
  });
}

function testImportPublicJwkRefusesACompromisedKey() {
  var good = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "jwk control")).publicKey.export({ format: "jwk" });
  var bad = ck.ecKeyPair("prime256v1", 1n).publicKey.export({ format: "jwk" });
  check("importPublicJwk control: an ordinary JWK imports",
        b.crypto.importPublicJwk(good).asymmetricKeyType === "ec");
  check("importPublicJwk: a scalar-1 JWK throws crypto/compromised-key",
        _code(function () { b.crypto.importPublicJwk(bad); }) === "crypto/compromised-key");
  function ModError(code, message) { this.code = code; this.message = message; }
  var thrown = null;
  try { b.crypto.importPublicJwk(bad, { errorClass: ModError, code: "mod/bad-key", messagePrefix: "mod key: " }); }
  catch (e) { thrown = e; }
  check("importPublicJwk: a scalar-1 JWK throws the caller's error class with its code and prefix",
        thrown instanceof ModError && thrown.code === "mod/bad-key" && /^mod key: /.test(thrown.message) &&
        /compromised/.test(thrown.message), thrown && thrown.message);
  thrown = null;
  try {
    b.crypto.importPublicJwk(bad, { errorClass: ModError, code: "mod/bad-key", compromisedCode: "mod/compromised-key" });
  } catch (e) { thrown = e; }
  check("importPublicJwk: opts.compromisedCode names the code for a compromised key",
        thrown instanceof ModError && thrown.code === "mod/compromised-key", thrown && thrown.code);
}

function testVerdictsAreCached() {
  var pair = ck.ecKeyPair("secp384r1", 1n);
  var pem = pair.publicKey.export({ type: "spki", format: "pem" });
  var first = b.crypto.compromisedKey(pair.publicKey);
  var second = b.crypto.compromisedKey(pair.publicKey);
  check("compromisedKey: a repeated KeyObject returns the same verdict object", first !== null && first === second);
  var firstPem = b.crypto.compromisedKey(pem);
  var secondPem = b.crypto.compromisedKey(pem);
  check("compromisedKey: a repeated PEM string returns the same verdict object",
        firstPem !== null && firstPem === secondPem);
}

function testEveryNodeKeyFormIsRead() {
  var data = Buffer.from("payload", "utf8");
  var good = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "forms control"));
  var goodPem = good.publicKey.export({ type: "spki", format: "pem" });
  var goodSig = nodeCrypto.sign(null, data, good.privateKey);
  [["Buffer PEM", Buffer.from(goodPem)], ["{ key: pem }", { key: goodPem }],
   ["{ key, format: der, type: spki }", { key: good.publicKey.export({ type: "spki", format: "der" }), format: "der", type: "spki" }]]
    .forEach(function (f) {
      check("crypto.verify control: a valid signature with the key as " + f[0] + " verifies",
            _code(function () { if (!b.crypto.verify(data, goodSig, f[1])) throw new Error("false"); }) === "NO-THROW");
      check("compromisedKey control: an ordinary key as " + f[0] + " is not compromised", _id(f[1]) === null);
    });
  var bad = ck.ecKeyPair("prime256v1", 1n);
  var badPem = bad.publicKey.export({ type: "spki", format: "pem" });
  var badSig = nodeCrypto.sign(null, data, bad.privateKey);
  [["Buffer PEM", Buffer.from(badPem)], ["{ key: pem }", { key: badPem }]].forEach(function (f) {
    check("crypto.verify: a scalar-1 key as " + f[0] + " does not verify", b.crypto.verify(data, badSig, f[1]) === false);
    check("compromisedKey: a scalar-1 key as " + f[0] + " is small-ec-scalar", _id(f[1]) === "small-ec-scalar");
  });
}

function testMixedPemChecksTheKeyNodeUses() {
  var data = Buffer.from("payload", "utf8");
  var bad = ck.ecKeyPair("prime256v1", 1n);
  var badPem = bad.publicKey.export({ type: "spki", format: "pem" });
  var badSig = nodeCrypto.sign(null, data, bad.privateKey);
  var goodCertPem = ck.certPem(ck.P256_CONTROL_CA_DER);
  [["key then certificate", badPem + goodCertPem], ["certificate then key", goodCertPem + badPem]].forEach(function (f) {
    check("compromised key fixture: node verifies the scalar-1 signature with " + f[0],
          nodeCrypto.verify(null, data, f[1], badSig) === true);
    check("compromisedKey: a compromised key PEM with an ordinary certificate (" + f[0] + ") is reported",
          _id(f[1]) === "small-ec-scalar");
    check("crypto.verify: a compromised key PEM with an ordinary certificate (" + f[0] + ") does not verify",
          b.crypto.verify(data, badSig, f[1]) === false);
  });
  var badPrivPem = bad.privateKey.export({ type: "pkcs8", format: "pem" });
  check("compromisedKey: a compromised private key PEM followed by an ordinary certificate is reported",
        _id(badPrivPem + goodCertPem) === "small-ec-scalar");
}

function testCertificateLabelsNodeTrusts() {
  var der = ck.P384_COMPROMISED_CA_DER;
  var b64 = der.toString("base64").match(/.{1,64}/g).join("\n");
  var x509Label = "-----BEGIN X509 CERTIFICATE-----\n" + b64 + "\n-----END X509 CERTIFICATE-----\n";
  var aux = Buffer.from("3000", "hex");
  var trustedB64 = Buffer.concat([der, aux]).toString("base64").match(/.{1,64}/g).join("\n");
  var trustedLabel = "-----BEGIN TRUSTED CERTIFICATE-----\n" + trustedB64 + "\n-----END TRUSTED CERTIFICATE-----\n";
  [["X509 CERTIFICATE", x509Label], ["TRUSTED CERTIFICATE", trustedLabel]].forEach(function (f) {
    check("compromisedKey: a compromised certificate under the " + f[0] + " PEM label is reported",
          _id(f[1]) === "small-ec-scalar");
  });
}

function testCertificateWhoseKeyNodeCannotLoad() {
  var der = Buffer.from(ck.P256_CONTROL_CA_DER);
  var ecOid = Buffer.from("06072a8648ce3d0201", "hex");
  var swapped = Buffer.from("06072a03040506070a", "hex");
  var at = der.indexOf(ecOid);
  var odd = Buffer.concat([der.subarray(0, at), swapped, der.subarray(at + ecOid.length)]);
  var cert = new nodeCrypto.X509Certificate(odd);
  check("compromised key fixture: node parses the certificate but cannot load its key",
        _code(function () { return cert.publicKey; }) !== "NO-THROW");
  check("compromisedKey: a certificate whose key node cannot load but pki can read is not compromised",
        _code(function () { if (b.crypto.compromisedKey(odd) !== null) throw new Error("reported"); }) === "NO-THROW");
}

function _verdictAs(input) {
  try { var f = b.crypto.compromisedKey(input); return f === null ? null : f.id; }
  catch (e) { return "throws " + (e.code || e.message); }
}

function testCertificatePkiCannotParseIsJudgedByItsKey() {
  var bad = crafted.selfSignedCa(crafted.COMPROMISED, crafted.explicitFalseExtension());
  var good = crafted.selfSignedCa(crafted.CONTROL_CA, crafted.explicitFalseExtension());
  check("compromised key fixture: @blamejs/pki cannot parse a certificate whose extension encodes critical FALSE",
        pki.lint.certificate(bad, { profile: "key-compromise" }).findings.some(function (f) {
          return f.id === "lint/unparseable";
        }));
  [["DER", function (d) { return d; }], ["X509Certificate", function (d) { return new nodeCrypto.X509Certificate(d); }],
   ["PEM", ck.certPem]].forEach(function (form) {
    check("compromisedKey: a scalar-1 certificate @blamejs/pki cannot parse, as " + form[0] + ", is small-ec-scalar",
          _verdictAs(form[1](bad)) === "small-ec-scalar", _verdictAs(form[1](bad)));
    check("compromisedKey control: the same encoding with an ordinary key, as " + form[0] + ", is not compromised",
          _verdictAs(form[1](good)) === null, _verdictAs(form[1](good)));
  });
}

function testDerCertificateIsReadAsDerWhateverTextItCarries() {
  [["an ordinary certificate's PEM", crafted.CERT_PEM_TEXT], ["an ordinary key's PEM", crafted.KEY_PEM_TEXT]]
    .forEach(function (text) {
      var bad = crafted.selfSignedCa(crafted.COMPROMISED, crafted.textExtension(text[1]));
      var good = crafted.selfSignedCa(crafted.CONTROL_CA, crafted.textExtension(text[1]));
      check("compromised key fixture: the certificate carrying " + text[0] + " contains the text -----BEGIN",
            bad.indexOf("-----BEGIN ") !== -1);
      [["Buffer", bad], ["Uint8Array", new Uint8Array(bad)], ["X509Certificate", new nodeCrypto.X509Certificate(ck.certPem(bad))]]
        .forEach(function (form) {
          check("compromisedKey: a scalar-1 certificate carrying " + text[0] + ", as " + form[0] + ", is small-ec-scalar",
                _verdictAs(form[1]) === "small-ec-scalar", _verdictAs(form[1]));
        });
      check("compromisedKey control: an ordinary certificate carrying " + text[0] + " is not compromised",
            _verdictAs(good) === null, _verdictAs(good));
    });
  var junk = crafted.selfSignedCa(crafted.CONTROL_CA, crafted.textExtension(crafted.BEGIN_JUNK_TEXT));
  check("compromisedKey: an ordinary DER certificate carrying a '-----BEGIN junk' line is not compromised",
        _verdictAs(junk) === null, _verdictAs(junk));
  var junkBad = crafted.selfSignedCa(crafted.COMPROMISED, crafted.textExtension(crafted.BEGIN_JUNK_TEXT));
  check("compromisedKey: a scalar-1 DER certificate carrying a '-----BEGIN junk' line is small-ec-scalar",
        _verdictAs(junkBad) === "small-ec-scalar", _verdictAs(junkBad));
}

function testCertificateFromDerReadsTheDer() {
  var der = crafted.selfSignedCa(crafted.COMPROMISED, crafted.textExtension(crafted.CERT_PEM_TEXT));
  check("compromised key fixture: node's X509Certificate(buffer) reads the certificate embedded in the DER",
        Buffer.from(new nodeCrypto.X509Certificate(der).raw).equals(ck.P256_CONTROL_CA_DER));
  var cert = b.crypto._certificateFromDer(der);
  check("crypto._certificateFromDer: returns the certificate the DER encodes, not one written inside it",
        Buffer.from(cert.raw).equals(der));
  check("crypto._certificateFromDer: accepts a Uint8Array",
        Buffer.from(b.crypto._certificateFromDer(new Uint8Array(der)).raw).equals(der));
  check("crypto._certificateFromDer: throws on bytes that are not a certificate",
        _code(function () { b.crypto._certificateFromDer(Buffer.from("not a certificate")); }) !== "NO-THROW");
}

function testCertificateDerHelpersReadTheDer() {
  var peer = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "blamejs cert peer"));
  var decoyText = crafted.textExtension("\n" + ck.certPem(ck.P384_CONTROL_CA_DER));
  var der = crafted.rebuild(ck.P384_CONTROL_CA_DER, { publicKey: peer.publicKey, signingKey: peer.privateKey, extension: decoyText });
  var ownSpki = peer.publicKey.export({ type: "spki", format: "der" });
  check("compromised key fixture: node's X509Certificate(buffer) reads the decoy certificate inside the peer certificate",
        !new nodeCrypto.X509Certificate(der).publicKey.export({ type: "spki", format: "der" }).equals(ownSpki));

  var wantPin = nodeCrypto.createHash("sha256").update(ownSpki).digest("hex");
  check("crypto.spkiPin: a DER certificate carrying another certificate's PEM pins its own key",
        b.crypto.spkiPin(der).hex === wantPin, b.crypto.spkiPin(der).hex);
  check("crypto.spkiPin: the same certificate as PEM pins its own key",
        b.crypto.spkiPin(ck.certPem(der)).hex === wantPin);

  var kem = b.crypto.generateEncryptionKeyPair();
  var sealed = b.crypto.encryptEnvelopeAsCertPeer("for the peer", { peerCertDer: der, peerKemPubkey: kem.publicKey });
  var opened = _code(function () {
    if (b.crypto.decrypt(sealed, { privateKey: kem.privateKey, ecPrivateKey: peer.privateKey.export({ type: "pkcs8", format: "pem" }) })
        .toString("utf8") !== "for the peer") throw new Error("wrong plaintext");
  });
  check("crypto.encryptEnvelopeAsCertPeer: a peer certificate carrying another certificate's PEM seals to the peer's own key",
        opened === "NO-THROW", opened);
}

function testCertificateNeitherReaderCanJudgeThrows() {
  var der = crafted.unreadableCa();
  check("compromised key fixture: node parses the certificate but cannot load its key",
        _code(function () { return new nodeCrypto.X509Certificate(der).publicKey; }) !== "NO-THROW");
  check("compromised key fixture: @blamejs/pki cannot parse the certificate",
        pki.lint.certificate(der, { profile: "key-compromise" }).findings.some(function (f) {
          return f.id === "lint/unparseable";
        }));
  check("compromisedKey: a certificate neither node nor @blamejs/pki can judge throws crypto/bad-key",
        _verdictAs(der) === "throws crypto/bad-key" &&
        _verdictAs(new nodeCrypto.X509Certificate(der)) === "throws crypto/bad-key", _verdictAs(der));
  check("compromisedKey: a composite-key certificate node cannot load is judged by @blamejs/pki and is not compromised",
        _verdictAs(composite.COMPOSITE_CERT_DER) === null &&
        _verdictAs(new nodeCrypto.X509Certificate(composite.COMPOSITE_CERT_DER)) === null);
}

function testWrappedCertificateConstructor() {
  var der = crafted.selfSignedCa(crafted.COMPROMISED, crafted.textExtension("wrapped constructor"));
  var other = crafted.selfSignedCa(crafted.COMPROMISED, crafted.textExtension("wrapped constructor object"));
  var original = nodeCrypto.X509Certificate;
  var made = new original(other);
  var calls = 0;
  nodeCrypto.X509Certificate = function (value) { calls += 1; return new original(value); };
  var asDer, asObject;
  try {
    asDer = _verdictAs(der);
    asObject = _verdictAs(made);
  } finally {
    nodeCrypto.X509Certificate = original;
  }
  check("compromisedKey: a DER certificate is judged while X509Certificate is wrapped", asDer === "small-ec-scalar", asDer);
  check("compromisedKey: an X509Certificate is judged while X509Certificate is wrapped",
        asObject === "small-ec-scalar", asObject);
  check("compromisedKey: the wrapped constructor was called", calls > 0);
}

function testSignRefusesACompromisedKey() {
  var good = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "sign control"));
  var bad = ck.ecKeyPair("secp384r1", 1n);
  [["KeyObject", good.privateKey], ["PKCS#8 PEM", good.privateKey.export({ type: "pkcs8", format: "pem" })]]
    .forEach(function (f) {
      check("crypto.sign control: an ordinary private key as " + f[0] + " signs",
            Buffer.isBuffer(b.crypto.sign("payload", f[1])));
    });
  [["KeyObject", bad.privateKey], ["PKCS#8 PEM", bad.privateKey.export({ type: "pkcs8", format: "pem" })],
   ["PKCS#8 PEM followed by an ordinary certificate",
    bad.privateKey.export({ type: "pkcs8", format: "pem" }) + ck.certPem(ck.P384_CONTROL_CA_DER)]]
    .forEach(function (f) {
      check("crypto.sign: a private key whose scalar is 1 as " + f[0] + " throws crypto/compromised-key",
            _code(function () { b.crypto.sign("payload", f[1]); }) === "crypto/compromised-key");
    });
}

// A P-256 SubjectPublicKeyInfo with explicit domain parameters whose base
// point is `generator` and whose public point is `point`.
function _explicitP256Spki(generator, point) {
  var int = function (hex) { return asn1.writeInteger(Buffer.from(hex, "hex")); };
  var params = asn1.writeSequence([int("01"),
    asn1.writeSequence([asn1.writeOid("1.2.840.10045.1.1"),
      int("00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")]),
    asn1.writeSequence([
      asn1.writeOctetString(Buffer.from("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", "hex")),
      asn1.writeOctetString(Buffer.from("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", "hex"))]),
    asn1.writeOctetString(generator),
    int("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"), int("01")]);
  return asn1.writeSequence([asn1.writeSequence([asn1.writeOid("1.2.840.10045.2.1"), params]),
    asn1.writeBitString(point, 0)]);
}

function _uncompressedPoint(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
}

function testExplicitCurveParametersAreNotTrusted() {
  var standardG = _uncompressedPoint(ck.ecKeyPair("prime256v1", 1n).publicKey);
  var q = _uncompressedPoint(ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", "explicit generator Q")).publicKey);
  var standard = nodeCrypto.createPublicKey({ key: _explicitP256Spki(standardG, standardG), format: "der", type: "spki" });
  check("compromisedKey control: explicit parameters naming the standard P-256 generator are read as P-256",
        _id(standard) === "small-ec-scalar");
  var forged = nodeCrypto.createPublicKey({ key: _explicitP256Spki(q, q), format: "der", type: "spki" });
  check("compromised key fixture: node reads no named curve for a generator that is not the standard one",
        !forged.asymmetricKeyDetails.namedCurve);
  check("compromisedKey: an EC key whose explicit parameters make its own public point the generator throws crypto/bad-key",
        _code(function () { b.crypto.compromisedKey(forged); }) === "crypto/bad-key");
  check("crypto.verify: a key with a non-standard explicit generator verifies nothing",
        b.crypto.verify("payload", Buffer.alloc(64, 1), forged.export({ type: "spki", format: "pem" })) === false);
}

function testDerWithTrailingBytesIsNotReadAsItsEmbeddedPem() {
  var der = crafted.selfSignedCa(crafted.COMPROMISED, crafted.textExtension(crafted.CERT_PEM_TEXT));
  var trailing = Buffer.concat([der, Buffer.from([0])]);
  check("compromised key fixture: node reads the embedded certificate from DER followed by a byte",
        Buffer.from(new nodeCrypto.X509Certificate(trailing).raw).equals(ck.P256_CONTROL_CA_DER));
  check("compromisedKey: a scalar-1 DER certificate followed by a byte is not judged by its embedded PEM",
        _code(function () { b.crypto.compromisedKey(trailing); }) === "crypto/bad-key");
  var read = _code(function () {
    if (Buffer.from(b.crypto._x509(trailing).raw).equals(ck.P256_CONTROL_CA_DER)) throw new Error("read the embedded certificate");
  });
  check("crypto._x509: DER followed by a byte is not read as the certificate written inside it", read !== "read the embedded certificate", read);
}

function testEnvelopeAcceptsAPemPeerCertificate() {
  var peer = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "blamejs pem cert peer"));
  var der = crafted.rebuild(ck.P384_CONTROL_CA_DER, { publicKey: peer.publicKey, signingKey: peer.privateKey });
  var kem = b.crypto.generateEncryptionKeyPair();
  [["PEM string", ck.certPem(der)], ["PEM Buffer", Buffer.from(ck.certPem(der), "utf8")], ["DER", der]].forEach(function (form) {
    var opened = _code(function () {
      var sealed = b.crypto.encryptEnvelopeAsCertPeer("for the peer", { peerCertDer: form[1], peerKemPubkey: kem.publicKey });
      if (b.crypto.decrypt(sealed, { privateKey: kem.privateKey, ecPrivateKey: peer.privateKey.export({ type: "pkcs8", format: "pem" }) })
          .toString("utf8") !== "for the peer") throw new Error("wrong plaintext");
    });
    check("crypto.encryptEnvelopeAsCertPeer: a peer certificate given as " + form[0] + " seals to the peer", opened === "NO-THROW", opened);
  });
}

function testWrappedKeyObjectsAreRead() {
  var good = ck.ecKeyPair("secp384r1", ck.labelScalar("secp384r1", "wrapped key object control"));
  var bad = ck.ecKeyPair("secp384r1", 1n);
  var sig = b.crypto.sign("payload", good.privateKey);
  var verified = _code(function () {
    if (b.crypto.verify("payload", sig, { key: good.publicKey }) !== true) throw new Error("did not verify");
  });
  check("crypto.verify: a valid signature verifies under { key: publicKeyObject }", verified === "NO-THROW", verified);
  check("compromisedKey: { key: publicKeyObject } for an ordinary key is not compromised",
        b.crypto.compromisedKey({ key: good.publicKey }) === null);
  check("compromisedKey: { key: privateKeyObject } for an ordinary key is not compromised",
        b.crypto.compromisedKey({ key: good.privateKey }) === null);
  check("compromisedKey: { key: publicKeyObject } whose scalar is 1 is small-ec-scalar",
        _id({ key: bad.publicKey }) === "small-ec-scalar");
}

async function testPrivateCryptoKeysAreJudgedByTheirPublicHalf() {
  var subtle = nodeCrypto.webcrypto.subtle;
  var ordinary = [
    ["Ed25519", await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])],
    ["RSASSA-PKCS1-v1_5", await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])],
    ["ECDSA P-384", await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"])],
  ];
  ordinary.forEach(function (f) {
    var out;
    try { out = b.crypto.compromisedKey(f[1].privateKey); }
    catch (e) { out = "threw " + (e.code || e.message); }
    check("compromisedKey: an ordinary private " + f[0] + " CryptoKey is not compromised", out === null, String(out));
  });
  var bad = ck.ecKeyPair("secp384r1", 1n);
  var badKey = await subtle.importKey("pkcs8", bad.privateKey.export({ type: "pkcs8", format: "der" }),
    { name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);
  check("compromisedKey: a private ECDSA CryptoKey whose scalar is 1 is small-ec-scalar",
        _id(badKey) === "small-ec-scalar");
}

async function run() {
  await testPrivateCryptoKeysAreJudgedByTheirPublicHalf();
  testWrappedKeyObjectsAreRead();
  testExplicitCurveParametersAreNotTrusted();
  testDerWithTrailingBytesIsNotReadAsItsEmbeddedPem();
  testEnvelopeAcceptsAPemPeerCertificate();
  testCurveOrdersAreRight();
  testSignRefusesACompromisedKey();
  testEveryNodeKeyFormIsRead();
  testMixedPemChecksTheKeyNodeUses();
  testCertificateLabelsNodeTrusts();
  testCertificateWhoseKeyNodeCannotLoad();
  testCertificatePkiCannotParseIsJudgedByItsKey();
  testDerCertificateIsReadAsDerWhateverTextItCarries();
  testCertificateFromDerReadsTheDer();
  testCertificateDerHelpersReadTheDer();
  testCertificateNeitherReaderCanJudgeThrows();
  testWrappedCertificateConstructor();
  testVerifyRefusesACompromisedKey();
  testImportPublicJwkRefusesACompromisedKey();
  testVerdictsAreCached();
  testSmallScalarBoundaries();
  await testEveryKeyFormAgrees();
  testListedKeyInEveryEncoding();
  testAgreesWithPkiLint();
  testOrdinaryKeysOfEveryType();
  testUnreadableInputThrows();
  testAssertNotCompromised();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
