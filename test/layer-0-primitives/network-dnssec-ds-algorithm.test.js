// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.dnssec.verifyDs checks the DS algorithm field against the
 * DNSKEY's algorithm (RFC 4035 §5.2). A DS whose digest matches the DNSKEY but
 * whose algorithm names a different one throws `dnssec/ds-mismatch`, and
 * verifyChain does not count such a DS or trust anchor. Each refusal has a
 * control that differs only in the algorithm field.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var ck      = require("../helpers/compromised-keys");

var dnssec = b.network.dns.dnssec;
var NOW = Math.floor(Date.now() / 1000);

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

function _dnskey(label) {
  var pair = ck.ecKeyPair("prime256v1", ck.labelScalar("prime256v1", label));
  var jwk = pair.publicKey.export({ format: "jwk" });
  var raw = Buffer.concat([Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  var rdata = Buffer.concat([_u16(257), Buffer.from([3, 13]), raw]);
  return { privateKey: pair.privateKey, rdata: rdata, tag: dnssec.keyTag(rdata) };
}

function _digest(owner, rdata) {
  return nodeCrypto.createHash("sha256").update(Buffer.concat([_wireName(owner), rdata])).digest();
}

function _sign(key, owner, typeNum, rdatas, signer) {
  var labels = owner.replace(/\.$/, "") === "" ? 0 : owner.replace(/\.$/, "").split(".").length;
  var rrsig = { algorithm: 13, labels: labels, originalTtl: 3600, expiration: NOW + 86400,
                inception: NOW - 3600, keyTag: key.tag, signerName: signer };
  var parts = [Buffer.concat([_u16(typeNum), Buffer.from([13, labels]), _u32(3600),
    _u32(rrsig.expiration), _u32(rrsig.inception), _u16(key.tag), _wireName(signer)])];
  rdatas.slice().sort(Buffer.compare).forEach(function (rd) {
    parts.push(_wireName(owner), _u16(typeNum), _u16(1), _u32(3600), _u16(rd.length), rd);
  });
  rrsig.signature = nodeCrypto.sign("sha256", Buffer.concat(parts), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return rrsig;
}

function _code(fn) {
  try { return { ok: true, value: fn() }; }
  catch (e) { return { ok: false, code: e && e.code, message: e && e.message }; }
}

function testVerifyDsChecksTheAlgorithm() {
  var key = _dnskey("blamejs dnssec ds-algorithm fixture child key");
  function attempt(algorithm) {
    return _code(function () {
      return dnssec.verifyDs({ ownerName: "victim.example", dnskeyRdata: key.rdata,
        ds: { keyTag: key.tag, algorithm: algorithm, digestType: 2, digest: _digest("victim.example", key.rdata) } });
    });
  }
  var control = attempt(13);
  check("dnssec ds algorithm control: verifyDs accepts a DS whose algorithm is the DNSKEY's",
        control.ok === true && control.value.ok === true, JSON.stringify(control));
  var other = attempt(8);
  check("dnssec ds algorithm: verifyDs refuses a DS whose algorithm differs from the DNSKEY's",
        other.ok === false && other.code === "dnssec/ds-mismatch", JSON.stringify(other));
  var missing = attempt(undefined);
  check("dnssec ds algorithm: verifyDs refuses a DS with no algorithm",
        missing.ok === false && missing.code === "dnssec/ds-mismatch", JSON.stringify(missing));
}

function testVerifyChainDoesNotCountADsNamingAnotherAlgorithm() {
  var root = _dnskey("blamejs dnssec ds-algorithm fixture root key");
  var child = _dnskey("blamejs dnssec ds-algorithm fixture child key");
  function chain(anchorAlg, dsAlg) {
    var dsRd = Buffer.concat([_u16(child.tag), Buffer.from([dsAlg, 2]), _digest("victim.example", child.rdata)]);
    return _code(function () {
      return dnssec.verifyChain({
        trustAnchors: [{ keyTag: root.tag, algorithm: anchorAlg, digestType: 2, digest: _digest(".", root.rdata) }],
        links: [
          { zone: ".", dnskeys: [root.rdata], dnskeyRrsig: _sign(root, ".", 48, [root.rdata], ".") },
          { zone: "victim.example", dnskeys: [child.rdata],
            dnskeyRrsig: _sign(child, "victim.example", 48, [child.rdata], "victim.example"),
            dsRdatas: [dsRd], dsRrsig: _sign(root, "victim.example", 43, [dsRd], ".") },
        ],
      });
    });
  }
  var control = chain(13, 13);
  check("dnssec ds algorithm control: verifyChain accepts an anchor and a DS that name the key's algorithm",
        control.ok === true && control.value.zone === "victim.example", JSON.stringify(control));
  var anchor = chain(8, 13);
  check("dnssec ds algorithm: verifyChain does not count a trust anchor that names another algorithm",
        anchor.ok === false && anchor.code === "dnssec/chain-anchor-mismatch", JSON.stringify(anchor));
  var ds = chain(13, 8);
  check("dnssec ds algorithm: verifyChain does not count a DS that names another algorithm",
        ds.ok === false && ds.code === "dnssec/chain-ds-mismatch", JSON.stringify(ds));
}

async function run() {
  testVerifyDsChecksTheAlgorithm();
  testVerifyChainDoesNotCountADsNamingAnotherAlgorithm();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK", helpers.getChecks(), "checks"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
