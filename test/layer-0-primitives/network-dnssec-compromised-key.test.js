// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.dnssec refuses a DNSKEY whose private key anyone can hold:
 * an ECDSA P-256 / P-384 key whose private scalar is 1 or n - 1, and an RSA
 * key on the published compromised-key list (eDellRoot). The refusal is
 * `dnssec/compromised-key` from verifyRrset and from verifyChain, whether the
 * key is the anchored root KSK, a child KSK vouched for by a parent DS, or a
 * parent ZSK that signs the child's DS. A ZSK that verifyChain returns without
 * using is refused when an answer is checked with it. Every refusal has a
 * control that differs only in the private scalar.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var dnssec = b.network.dns.dnssec;
var NOW = Math.floor(Date.now() / 1000);

var CURVES = [
  { curve: "prime256v1", alg: 13, hash: "sha256", width: 32 },
  { curve: "secp384r1",  alg: 14, hash: "sha384", width: 48 },
];

function _u16(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }
function _u32(n) { var x = Buffer.alloc(4); x.writeUInt32BE(n >>> 0, 0); return x; }
function _wireName(name) {
  var n = name.replace(/\.$/, "");
  if (n === "") return Buffer.from([0]);
  var parts = [];
  n.split(".").forEach(function (label) {
    var x = Buffer.from(label.toLowerCase(), "ascii");
    parts.push(Buffer.from([x.length]), x);
  });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}
function _labelCount(name) { var n = name.replace(/\.$/, ""); return n === "" ? 0 : n.split(".").length; }

function _ecDnskey(spec, d, flags) {
  var pair = ck.ecKeyPair(spec.curve, d);
  var jwk = pair.publicKey.export({ format: "jwk" });
  var raw = Buffer.concat([Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  var rdata = Buffer.concat([_u16(flags === undefined ? 257 : flags), Buffer.from([3, spec.alg]), raw]);
  return { privateKey: pair.privateKey, publicKey: raw, rdata: rdata, tag: dnssec.keyTag(rdata), spec: spec };
}

function _sign(key, owner, typeNum, rdatas, signer) {
  var rrsig = {
    algorithm: key.spec.alg, labels: _labelCount(owner), originalTtl: 3600,
    expiration: NOW + 86400, inception: NOW - 3600, keyTag: key.tag, signerName: signer,
  };
  var parts = [Buffer.concat([_u16(typeNum), Buffer.from([rrsig.algorithm, rrsig.labels]), _u32(3600),
    _u32(rrsig.expiration), _u32(rrsig.inception), _u16(key.tag), _wireName(signer)])];
  rdatas.slice().sort(Buffer.compare).forEach(function (rd) {
    parts.push(_wireName(owner), _u16(typeNum), _u16(1), _u32(3600), _u16(rd.length), rd);
  });
  rrsig.signature = nodeCrypto.sign(key.spec.hash, Buffer.concat(parts), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return rrsig;
}

function _dsDigest(owner, rdata) {
  return nodeCrypto.createHash("sha256").update(Buffer.concat([_wireName(owner), rdata])).digest();
}

function _code(fn) {
  try { return { ok: true, value: fn() }; }
  catch (e) { return { ok: false, code: e && e.code, message: e && e.message }; }
}

// The private scalars under test: 1 on P-256, n - 1 on P-384.
function _compromisedScalar(spec) {
  return spec.curve === "prime256v1" ? 1n : ck.CURVES[spec.curve][2] - 1n;
}

function _verifyA(key) {
  var a = Buffer.from([192, 0, 2, 66]);
  return _code(function () {
    return dnssec.verifyRrset({
      name: "www.victim.example", type: "A", rdatas: [a],
      rrsig: _sign(key, "www.victim.example", 1, [a], "victim.example"),
      dnskey: { algorithm: key.spec.alg, publicKey: key.publicKey },
    });
  });
}

function testVerifyRrsetRefusesACompromisedDnskey() {
  CURVES.forEach(function (spec) {
    var control = _verifyA(_ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture zone key")));
    check("dnssec compromised key control: verifyRrset accepts an ordinary " + spec.curve + " DNSKEY",
          control.ok === true && control.value.ok === true, JSON.stringify(control));
    var bad = _verifyA(_ecDnskey(spec, _compromisedScalar(spec)));
    check("dnssec compromised key: verifyRrset refuses a " + spec.curve + " DNSKEY anyone can sign with",
          bad.ok === false && bad.code === "dnssec/compromised-key", JSON.stringify(bad));
  });
}

function testVerifyDsRefusesACompromisedDnskey() {
  CURVES.forEach(function (spec) {
    function attempt(key) {
      return _code(function () {
        return dnssec.verifyDs({
          ownerName: "victim.example", dnskeyRdata: key.rdata,
          ds: { keyTag: key.tag, algorithm: spec.alg, digestType: 2, digest: _dsDigest("victim.example", key.rdata) },
        });
      });
    }
    var control = attempt(_ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture child key")));
    check("dnssec compromised key control: verifyDs accepts a DS for an ordinary " + spec.curve + " DNSKEY",
          control.ok === true && control.value.ok === true, JSON.stringify(control));
    var bad = attempt(_ecDnskey(spec, _compromisedScalar(spec)));
    check("dnssec compromised key: verifyDs refuses a DS that vouches for a " + spec.curve + " DNSKEY anyone can sign with",
          bad.ok === false && bad.code === "dnssec/compromised-key", JSON.stringify(bad));
  });
  var unknownAlg = Buffer.concat([_u16(257), Buffer.from([3, 253]), Buffer.from("opaque private-algorithm key", "utf8")]);
  var unknown = _code(function () {
    return dnssec.verifyDs({
      ownerName: "victim.example", dnskeyRdata: unknownAlg,
      ds: { keyTag: dnssec.keyTag(unknownAlg), algorithm: 253, digestType: 2, digest: _dsDigest("victim.example", unknownAlg) },
    });
  });
  check("dnssec compromised key control: verifyDs still matches a DS for a DNSKEY algorithm it cannot import",
        unknown.ok === true && unknown.value.ok === true, JSON.stringify(unknown));
}

function _rootLink(key) {
  return { zone: ".", dnskeys: [key.rdata], dnskeyRrsig: _sign(key, ".", 48, [key.rdata], ".") };
}
function _anchorFor(key) {
  return [{ keyTag: key.tag, algorithm: key.spec.alg, digestType: 2, digest: _dsDigest(".", key.rdata) }];
}

function testVerifyChainRefusesACompromisedAnchoredRoot() {
  CURVES.forEach(function (spec) {
    var good = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture root key"));
    var control = _code(function () { return dnssec.verifyChain({ trustAnchors: _anchorFor(good), links: [_rootLink(good)] }); });
    check("dnssec compromised key control: verifyChain accepts an ordinary " + spec.curve + " anchored root key",
          control.ok === true && control.value.ok === true, JSON.stringify(control));
    var weak = _ecDnskey(spec, _compromisedScalar(spec));
    var bad = _code(function () { return dnssec.verifyChain({ trustAnchors: _anchorFor(weak), links: [_rootLink(weak)] }); });
    check("dnssec compromised key: verifyChain refuses a " + spec.curve + " anchored root key anyone can sign with",
          bad.ok === false && bad.code === "dnssec/compromised-key", JSON.stringify(bad));
  });
}

function _childChain(root, child) {
  var dsRd = Buffer.concat([_u16(child.tag), Buffer.from([child.spec.alg, 2]), _dsDigest("victim.example", child.rdata)]);
  return {
    trustAnchors: _anchorFor(root),
    links: [
      _rootLink(root),
      { zone: "victim.example", dnskeys: [child.rdata],
        dnskeyRrsig: _sign(child, "victim.example", 48, [child.rdata], "victim.example"),
        dsRdatas: [dsRd], dsRrsig: _sign(root, "victim.example", 43, [dsRd], ".") },
    ],
  };
}

function testVerifyChainRefusesACompromisedChildKsk() {
  CURVES.forEach(function (spec) {
    var root = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture root key"));
    var goodChild = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture child key"));
    var control = _code(function () { return dnssec.verifyChain(_childChain(root, goodChild)); });
    check("dnssec compromised key control: verifyChain accepts an ordinary " + spec.curve + " child KSK under its DS",
          control.ok === true && control.value.ok === true && control.value.zone === "victim.example", JSON.stringify(control));
    var weakChild = _ecDnskey(spec, _compromisedScalar(spec));
    var bad = _code(function () { return dnssec.verifyChain(_childChain(root, weakChild)); });
    check("dnssec compromised key: verifyChain refuses a " + spec.curve + " child KSK anyone can sign with, though its DS matches",
          bad.ok === false && bad.code === "dnssec/compromised-key", JSON.stringify(bad));
  });
}

// The root's DNSKEY set is [KSK, ZSK]. The anchored KSK signs the set and the
// ZSK signs the child's DS, so the parent key that vouches for the child is
// one the trust anchor never names.
function _zskSignedDsChain(rootKsk, rootZsk, child) {
  var dsRd = Buffer.concat([_u16(child.tag), Buffer.from([child.spec.alg, 2]), _dsDigest("victim.example", child.rdata)]);
  var rootKeys = [rootKsk.rdata, rootZsk.rdata];
  return {
    trustAnchors: _anchorFor(rootKsk),
    links: [
      { zone: ".", dnskeys: rootKeys, dnskeyRrsig: _sign(rootKsk, ".", 48, rootKeys, ".") },
      { zone: "victim.example", dnskeys: [child.rdata],
        dnskeyRrsig: _sign(child, "victim.example", 48, [child.rdata], "victim.example"),
        dsRdatas: [dsRd], dsRrsig: _sign(rootZsk, "victim.example", 43, [dsRd], ".") },
    ],
  };
}

function testVerifyChainRefusesACompromisedParentZskSigningTheDs() {
  CURVES.forEach(function (spec) {
    var ksk = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture root key"));
    var child = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture child key"));
    var goodZsk = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture root zsk"), 256);
    var control = _code(function () { return dnssec.verifyChain(_zskSignedDsChain(ksk, goodZsk, child)); });
    check("dnssec compromised key control: verifyChain accepts a child DS signed by an ordinary " + spec.curve + " parent ZSK",
          control.ok === true && control.value.ok === true && control.value.zone === "victim.example", JSON.stringify(control));
    var weakZsk = _ecDnskey(spec, _compromisedScalar(spec), 256);
    var bad = _code(function () { return dnssec.verifyChain(_zskSignedDsChain(ksk, weakZsk, child)); });
    check("dnssec compromised key: verifyChain refuses a child DS signed by a " + spec.curve + " parent ZSK anyone can sign with",
          bad.ok === false && bad.code === "dnssec/compromised-key", JSON.stringify(bad));
  });
}

// The leaf zone's DNSKEY set is [KSK, ZSK] and only the KSK signs the set, so
// verifyChain returns the ZSK without using it. The answer is then checked
// with the returned ZSK.
function testVerifyRrsetRefusesACompromisedZskThatVerifyChainReturned() {
  CURVES.forEach(function (spec) {
    var root = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture root key"));
    var ksk = _ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture child key"));
    function answerWith(zsk) {
      var keys = [ksk.rdata, zsk.rdata];
      var dsRd = Buffer.concat([_u16(ksk.tag), Buffer.from([ksk.spec.alg, 2]), _dsDigest("victim.example", ksk.rdata)]);
      var trusted = dnssec.verifyChain({
        trustAnchors: _anchorFor(root),
        links: [
          _rootLink(root),
          { zone: "victim.example", dnskeys: keys, dnskeyRrsig: _sign(ksk, "victim.example", 48, keys, "victim.example"),
            dsRdatas: [dsRd], dsRrsig: _sign(root, "victim.example", 43, [dsRd], ".") },
        ],
      });
      var returned = trusted.keys.filter(function (rd) { return dnssec.keyTag(rd) === zsk.tag; })[0];
      var a = Buffer.from([192, 0, 2, 66]);
      return _code(function () {
        return dnssec.verifyRrset({
          name: "www.victim.example", type: "A", rdatas: [a],
          rrsig: _sign(zsk, "www.victim.example", 1, [a], "victim.example"),
          dnskey: { algorithm: returned[3], publicKey: returned.subarray(4) },
        });
      });
    }
    var control = answerWith(_ecDnskey(spec, ck.labelScalar(spec.curve, "blamejs dnssec fixture zone key"), 256));
    check("dnssec compromised key control: an answer signed by an ordinary " + spec.curve + " ZSK from verifyChain's keys verifies",
          control.ok === true && control.value.ok === true, JSON.stringify(control));
    var bad = answerWith(_ecDnskey(spec, _compromisedScalar(spec), 256));
    check("dnssec compromised key: an answer signed by a " + spec.curve + " ZSK from verifyChain's keys that anyone can sign with is refused",
          bad.ok === false && bad.code === "dnssec/compromised-key", JSON.stringify(bad));
  });
}

function _rsaDnskeyPublicKey(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  var e = Buffer.from(jwk.e, "base64url");
  return Buffer.concat([Buffer.from([e.length]), e, Buffer.from(jwk.n, "base64url")]);
}

function testVerifyRrsetRefusesAListedRsaDnskey() {
  var a = Buffer.from([192, 0, 2, 66]);
  function attempt(publicKey) {
    return _code(function () {
      return dnssec.verifyRrset({
        name: "victim.example", type: "A", rdatas: [a],
        rrsig: { algorithm: 8, labels: 2, originalTtl: 3600, expiration: NOW + 86400, inception: NOW - 3600,
                 keyTag: 1, signerName: "victim.example", signature: Buffer.alloc(256, 1) },
        dnskey: { algorithm: 8, publicKey: _rsaDnskeyPublicKey(publicKey) },
      });
    });
  }
  var ordinary = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
  var control = attempt(ordinary);
  check("dnssec compromised key control: an ordinary RSA DNSKEY reaches the signature check",
        control.ok === false && control.code === "dnssec/bad-signature", JSON.stringify(control));
  var listed = attempt(new nodeCrypto.X509Certificate(ck.EDELLROOT_CERT_PEM).publicKey);
  check("dnssec compromised key: verifyRrset refuses the listed eDellRoot RSA key as a DNSKEY",
        listed.ok === false && listed.code === "dnssec/compromised-key", JSON.stringify(listed));
}

async function run() {
  testVerifyRrsetRefusesACompromisedDnskey();
  testVerifyDsRefusesACompromisedDnskey();
  testVerifyChainRefusesACompromisedAnchoredRoot();
  testVerifyChainRefusesACompromisedChildKsk();
  testVerifyChainRefusesACompromisedParentZskSigningTheDs();
  testVerifyRrsetRefusesACompromisedZskThatVerifyChainReturned();
  testVerifyRrsetRefusesAListedRsaDnskey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
