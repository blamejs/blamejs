// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * X.509 basicConstraints pathLenConstraint enforcement (RFC 5280 §4.2.1.9 /
 * §6.1.4) via b.x509Chain.pathLenSatisfied.
 *
 * node:crypto X509Certificate does not expose pathLenConstraint, so a chain
 * whose links each verify (issuerValidlyIssued true for every pair) can still
 * exceed a CA's stated path length: a root with pathLen:0 that vouches for an
 * intermediate which in turn issues the leaf. openssl rejects that (error 25,
 * path length exceeded); the framework's walkers did not, because the check
 * did not exist. This proves the new primitive rejects an over-long chain that
 * every issuerValidlyIssued link accepts, and accepts a within-limit chain.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("crypto");
var pki  = require("../../lib/vendor/blamejs-pki.cjs");
var x509Chain = require("../../lib/x509-chain");
var asn1 = require("../../lib/asn1-der");

// Raw X.509 Name DER holding a single CN of the given ASN.1 string type + bytes,
// for exercising non-UTF8 directory-string decoding. pki.x509.sign accepts raw
// Name DER for subject/issuer.
function _rawCn(stringTag, valueBytes) {
  return asn1.writeSequence([
    asn1.writeSet([
      asn1.writeSequence([
        asn1.writeOid("2.5.4.3"),
        asn1.writeNode(stringTag, Buffer.from(valueBytes)),
      ]),
    ]),
  ]);
}

async function _spki(publicKey) {
  return Buffer.from(await pki.webcrypto.subtle.exportKey("spki", publicKey));
}

// Mint root(cA:TRUE, pathLen:rootPathLen) -> interCount intermediate CAs -> leaf,
// returning node X509Certificate objects leaf-first: [leaf, interN..inter1, root].
// Each cert is signed with the issuer's raw key (name + SPKI), so the chain links
// all verify regardless of the path-length policy under test.
async function _mintPathChain(opts) {
  opts = opts || {};
  var rootPathLen = opts.rootPathLen;              // number | undefined (omit → unconstrained)
  var interCount  = typeof opts.interCount === "number" ? opts.interCount : 1;
  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  var alg = { name: "ECDSA", namedCurve: "P-256" };

  var rootKeys = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var rootSpki = await _spki(rootKeys.publicKey);
  function _signRoot(pathLen) {
    var bc = { cA: true, critical: true };
    if (typeof pathLen === "number") bc.pathLen = pathLen;
    return pki.x509.sign({
      subject: "PL Root CA", subjectPublicKey: rootSpki,
      serialNumber: "01", notBefore: now, notAfter: notAfter,
      extensions: { basicConstraints: bc, keyUsage: ["keyCertSign", "cRLSign"], keyUsageCritical: true },
    }, { key: rootKeys.privateKey }, { pem: true });
  }
  var rootPem = await _signRoot(rootPathLen);
  // A second self-issued root with the SAME subject + key but a different
  // pathLen, for exercising anchor-ordering (a stricter anchor must not preempt
  // a permissive one that also matches).
  var rootPemAlt = typeof opts.altRootPathLen === "number" ? await _signRoot(opts.altRootPathLen) : null;

  // Build intermediates from the root down. issuerName/issuerSpki/issuerKey start
  // at the root and advance to each freshly minted intermediate.
  var issuerName = "PL Root CA", issuerSpki = rootSpki, issuerKey = rootKeys.privateKey;
  var interPems = [];
  for (var n = 0; n < interCount; n += 1) {
    var keys = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    var spki = await _spki(keys.publicKey);
    var subj = "PL Intermediate " + (n + 1);
    var pem = await pki.x509.sign({
      subject: subj, subjectPublicKey: spki,
      serialNumber: "1" + n, notBefore: now, notAfter: notAfter,
      extensions: { basicConstraints: { cA: true, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
    }, { name: issuerName, publicKey: issuerSpki, key: issuerKey }, { pem: true });
    interPems.push(pem);
    issuerName = subj; issuerSpki = spki; issuerKey = keys.privateKey;
  }

  var leafKeys = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var leafSpki = await _spki(leafKeys.publicKey);
  var leafPem = await pki.x509.sign({
    subject: "pl-leaf.example", subjectPublicKey: leafSpki,
    serialNumber: "99", notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true },
  }, { name: issuerName, publicKey: issuerSpki, key: issuerKey }, { pem: true });

  var leafPkcs8 = await pki.webcrypto.subtle.exportKey("pkcs8", leafKeys.privateKey);
  var leafKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(leafPkcs8).toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END PRIVATE KEY-----\n";

  // Assemble leaf-first: [leaf, interN, ..., inter1, root].
  var chainPems = [leafPem].concat(interPems.slice().reverse()).concat([rootPem]);
  return {
    certs:      chainPems.map(function (pem) { return new nodeCrypto.X509Certificate(pem); }),
    chainPems:  chainPems,
    leafPem:    leafPem,
    rootPem:    rootPem,
    rootPemAlt: rootPemAlt,
    leafKeyPem: leafKeyPem,
  };
}

function _b64url(buf) { return Buffer.from(buf).toString("base64url"); }
function _mds3Blob(payload, leafKeyPem, chainPemsLeafFirst) {
  var x5c = chainPemsLeafFirst.map(function (pem) {
    return pem.replace(/-----BEGIN CERTIFICATE-----/g, "")
              .replace(/-----END CERTIFICATE-----/g, "").replace(/\s+/g, "");
  });
  var header = { alg: "ES256", typ: "JWT", x5c: x5c };
  var signingInput = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"),
    { key: leafKeyPem, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + _b64url(sig);
}

async function run() {
  check("b.x509Chain.pathLenSatisfied is exposed", typeof b.x509Chain.pathLenSatisfied === "function");

  // THE FAIL-OPEN: root pathLen:0 vouches for an intermediate that issues the leaf.
  // Every link verifies, but the root permits zero intermediate CAs below it.
  var over = await _mintPathChain({ rootPathLen: 0, interCount: 1 });
  check("over-long: every issuerValidlyIssued link accepts the chain (the gap)",
        x509Chain.issuerValidlyIssued(over.certs[2], over.certs[1]) === true &&
        x509Chain.issuerValidlyIssued(over.certs[1], over.certs[0]) === true);
  check("over-long: pathLenSatisfied REJECTS a chain past the root's pathLen:0",
        x509Chain.pathLenSatisfied(over.certs) === false);

  // Control: root pathLen:1 permits exactly one intermediate.
  var okOne = await _mintPathChain({ rootPathLen: 1, interCount: 1 });
  check("within-limit: root pathLen:1 with one intermediate is accepted",
        x509Chain.pathLenSatisfied(okOne.certs) === true);

  // Two intermediates under pathLen:1 is one too many.
  var overTwo = await _mintPathChain({ rootPathLen: 1, interCount: 2 });
  check("over-long: root pathLen:1 with two intermediates is REJECTED",
        x509Chain.pathLenSatisfied(overTwo.certs) === false);

  // Control: root pathLen:2 permits two intermediates.
  var okTwo = await _mintPathChain({ rootPathLen: 2, interCount: 2 });
  check("within-limit: root pathLen:2 with two intermediates is accepted",
        x509Chain.pathLenSatisfied(okTwo.certs) === true);

  // A pathLen:0 CA issuing the leaf DIRECTLY (no intermediate) is fine.
  var direct = await _mintPathChain({ rootPathLen: 0, interCount: 0 });
  check("within-limit: pathLen:0 root issuing the leaf directly is accepted",
        x509Chain.pathLenSatisfied(direct.certs) === true);

  // A root with NO pathLenConstraint imposes no limit.
  var unconstrained = await _mintPathChain({ interCount: 2 });
  check("no pathLenConstraint: any depth is accepted",
        x509Chain.pathLenSatisfied(unconstrained.certs) === true);

  // Fail closed on a malformed chain.
  check("fail-closed: a chain with a missing cert returns false",
        x509Chain.pathLenSatisfied([null, unconstrained.certs[1]]) === false);
  check("degenerate: a single-cert chain has no CA link to constrain",
        x509Chain.pathLenSatisfied([unconstrained.certs[0]]) === true);

  // ---- Consumer path: b.auth.fidoMds3.fetch must refuse a BLOB whose x5c is an
  // over-long chain (root pathLen:0 -> intermediate -> leaf). The leaf GENUINELY
  // signs the BLOB and every link verifies, so without pathLen enforcement the
  // attacker-forged metadata would be accepted.
  var mds3Payload = {
    legalHeader: "Test BLOB", no: 1,
    nextUpdate: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef",
                metadataStatement: { description: "Test entry" },
                statusReports: [{ status: "FIDO_CERTIFIED_L2" }] }],
  };
  var forgedBlob = _mds3Blob(mds3Payload, over.leafKeyPem, [over.leafPem].concat(
    over.chainPems.slice(1, over.chainPems.length - 1)));   // [leaf, intermediate] (root supplied as anchor)
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(forgedBlob, "ascii") };
    },
  });
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);
  var mdsThrew = null;
  try {
    await fm.fetch({ url: "https://test.invalid/mds3", caCertificate: over.rootPem, force: true });
  } catch (e) { mdsThrew = e; }
  finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
  check("fido-mds3.fetch: over-long x5c (root pathLen:0) is REJECTED",
        mdsThrew && mdsThrew.code === "fido-mds3/chain-pathlen-exceeded");

  // Anchor ordering: with BOTH a pathLen:0 and a pathLen:1 root (same subject +
  // key) in the trust bundle, the chain the strict anchor forbids is permitted
  // by the other, and must be accepted. A stricter matching anchor must not
  // preempt a permissive one.
  var twoRoot = await _mintPathChain({ rootPathLen: 0, altRootPathLen: 1, interCount: 1 });
  var twoRootBlob = _mds3Blob(mds3Payload, twoRoot.leafKeyPem,
    [twoRoot.leafPem].concat(twoRoot.chainPems.slice(1, twoRoot.chainPems.length - 1)));
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(twoRootBlob, "ascii") };
    },
  });
  delete require.cache[fmPath];
  var fm2 = require(fmPath);
  var twoRootErr = null;
  try {
    await fm2.fetch({ url: "https://test.invalid/mds3",
      caCertificate: [twoRoot.rootPem, twoRoot.rootPemAlt], force: true });
  } catch (e) { twoRootErr = e; }
  finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
  check("fido-mds3.fetch: a permissive anchor (pathLen:1) is tried after a strict one (pathLen:0)",
        !twoRootErr || (twoRootErr.code !== "fido-mds3/chain-pathlen-exceeded" &&
                        twoRootErr.code !== "fido-mds3/chain-not-anchored"));

  // A self-issued CA rollover whose subject and issuer are the same entity but
  // differ only in capitalization (RFC 5280 §7.1 treats them as equal) must NOT
  // consume path length. RED if names are compared by raw bytes: the rollover is
  // counted and a chain a pathLen:0 root permits is rejected.
  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  var alg = { name: "ECDSA", namedCurve: "P-256" };
  var rk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var rkSpki = await _spki(rk.publicKey);
  var rollRootPem = await pki.x509.sign({
    subject: "Rollover CA", subjectPublicKey: rkSpki, serialNumber: "01",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, pathLen: 0, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { key: rk.privateKey }, { pem: true });
  // Self-issued: subject and issuer are the same entity, differing only in case.
  var rolloverPem = await pki.x509.sign({
    subject: "rollover ca", subjectPublicKey: rkSpki, serialNumber: "02",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { name: "Rollover CA", publicKey: rkSpki, key: rk.privateKey }, { pem: true });
  var lk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var lkSpki = await _spki(lk.publicKey);
  var rollLeafPem = await pki.x509.sign({
    subject: "roll-leaf.example", subjectPublicKey: lkSpki, serialNumber: "03",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true },
  }, { name: "rollover ca", publicKey: rkSpki, key: rk.privateKey }, { pem: true });
  var rollChain = [rollLeafPem, rolloverPem, rollRootPem].map(function (p) {
    return new nodeCrypto.X509Certificate(p);
  });
  check("self-issued rollover with case-differing DN does not consume path length",
        x509Chain.pathLenSatisfied(rollChain) === true);

  // P1 regression: DN comparison must preserve RDN boundaries. A single-RDN
  // subject "CN=A O=B" must NOT be treated as equal to a two-RDN issuer rendered
  // "CN=A\nO=B", or a non-self-issued intermediate would be miscounted as
  // self-issued and skip the path-length decrement (a fail-open). Node renders
  // multiple RDNs newline-separated; collapsing that newline is the bug.
  var mrk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var mrkSpki = await _spki(mrk.publicKey);
  var twoRdnName = [{ commonName: "A" }, { organizationName: "B" }];
  var mergeRootPem = await pki.x509.sign({
    subject: twoRdnName, subjectPublicKey: mrkSpki, serialNumber: "01",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, pathLen: 0, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { key: mrk.privateKey }, { pem: true });
  var mik = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var mikSpki = await _spki(mik.publicKey);
  var mergeInterPem = await pki.x509.sign({
    subject: [{ commonName: "A O=B" }], subjectPublicKey: mikSpki, serialNumber: "02",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { name: twoRdnName, publicKey: mrkSpki, key: mrk.privateKey }, { pem: true });
  var mlk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var mlkSpki = await _spki(mlk.publicKey);
  var mergeLeafPem = await pki.x509.sign({
    subject: [{ commonName: "merge-leaf" }], subjectPublicKey: mlkSpki, serialNumber: "03",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true },
  }, { name: [{ commonName: "A O=B" }], publicKey: mikSpki, key: mik.privateKey }, { pem: true });
  var mergeChain = [mergeLeafPem, mergeInterPem, mergeRootPem].map(function (p) {
    return new nodeCrypto.X509Certificate(p);
  });
  check("RDN-boundary merge: a single-RDN subject is not conflated with a two-RDN issuer",
        x509Chain.pathLenSatisfied(mergeChain) === false);

  // A self-issued rollover whose issuer value has insignificant leading whitespace
  // (RFC 5280 §7.1) must still be recognized: comparing the DECODED value handles
  // it. RED if names are compared as raw bytes or node's escaped display strings.
  var esk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var eskSpki = await _spki(esk.publicKey);
  var escRootPem = await pki.x509.sign({
    subject: [{ commonName: "Esc CA" }], subjectPublicKey: eskSpki, serialNumber: "01",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, pathLen: 0, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { key: esk.privateKey }, { pem: true });
  var escInterPem = await pki.x509.sign({
    subject: [{ commonName: "Esc CA" }], subjectPublicKey: eskSpki, serialNumber: "02",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { name: [{ commonName: " Esc CA" }], publicKey: eskSpki, key: esk.privateKey }, { pem: true });
  var elk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var elkSpki = await _spki(elk.publicKey);
  var escLeafPem = await pki.x509.sign({
    subject: [{ commonName: "esc-leaf" }], subjectPublicKey: elkSpki, serialNumber: "03",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true },
  }, { name: [{ commonName: "Esc CA" }], publicKey: eskSpki, key: esk.privateKey }, { pem: true });
  var escChain = [escLeafPem, escInterPem, escRootPem].map(function (p) {
    return new nodeCrypto.X509Certificate(p);
  });
  check("self-issued rollover with escaped leading whitespace does not consume path length",
        x509Chain.pathLenSatisfied(escChain) === true);

  // P1 regression: non-UTF8 directory strings must not decode lossily. A
  // TeletexString (tag 0x14) CN of byte 0xE9 (é) and one of 0xE8 (è) are DISTINCT
  // names; decoding both as UTF-8 collapses them to U+FFFD and wrongly classifies
  // the intermediate as self-issued (a fail-open). The intermediate here is NOT
  // self-issued, so it must consume path length and the chain must be REJECTED.
  var T61 = 0x14;
  var tk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var tkSpki = await _spki(tk.publicKey);
  var t61RootPem = await pki.x509.sign({
    subject: _rawCn(T61, [0xe9]), subjectPublicKey: tkSpki, serialNumber: "01",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, pathLen: 0, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { key: tk.privateKey }, { pem: true });
  var tik = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var tikSpki = await _spki(tik.publicKey);
  var t61InterPem = await pki.x509.sign({
    subject: _rawCn(T61, [0xe8]), subjectPublicKey: tikSpki, serialNumber: "02",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { name: _rawCn(T61, [0xe9]), publicKey: tkSpki, key: tk.privateKey }, { pem: true });
  var tlk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var tlkSpki = await _spki(tlk.publicKey);
  var t61LeafPem = await pki.x509.sign({
    subject: [{ commonName: "t61-leaf" }], subjectPublicKey: tlkSpki, serialNumber: "03",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true },
  }, { name: _rawCn(T61, [0xe8]), publicKey: tikSpki, key: tik.privateKey }, { pem: true });
  var t61Chain = [t61LeafPem, t61InterPem, t61RootPem].map(function (p) {
    return new nodeCrypto.X509Certificate(p);
  });
  check("TeletexString names é and è are distinct: the intermediate consumes path length (rejected)",
        x509Chain.pathLenSatisfied(t61Chain) === false);

  // A self-issued rollover whose names are Unicode-compatibility-equivalent
  // (RFC 5280 §7.1 applies NFKC): a full-width "ＣＡ" and "CA" are the same name,
  // so the rollover must NOT consume path length. RED without NFKC normalization.
  var uk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var ukSpki = await _spki(uk.publicKey);
  var uRootPem = await pki.x509.sign({
    subject: [{ commonName: "CA" }], subjectPublicKey: ukSpki, serialNumber: "01",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, pathLen: 0, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { key: uk.privateKey }, { pem: true });
  var uInterPem = await pki.x509.sign({
    subject: [{ commonName: "ＣＡ" }], subjectPublicKey: ukSpki, serialNumber: "02",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: true, critical: true }, keyUsage: ["keyCertSign"], keyUsageCritical: true },
  }, { name: [{ commonName: "CA" }], publicKey: ukSpki, key: uk.privateKey }, { pem: true });
  var ulk = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var ulkSpki = await _spki(ulk.publicKey);
  var uLeafPem = await pki.x509.sign({
    subject: [{ commonName: "u-leaf" }], subjectPublicKey: ulkSpki, serialNumber: "03",
    notBefore: now, notAfter: notAfter,
    extensions: { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true },
  }, { name: [{ commonName: "ＣＡ" }], publicKey: ukSpki, key: uk.privateKey }, { pem: true });
  var uChain = [uLeafPem, uInterPem, uRootPem].map(function (p) {
    return new nodeCrypto.X509Certificate(p);
  });
  check("Unicode-compatibility-equivalent (NFKC) self-issued rollover does not consume path length",
        x509Chain.pathLenSatisfied(uChain) === true);

  console.log("OK — x509 pathLen enforcement (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
