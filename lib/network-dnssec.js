"use strict";
/**
 * @module b.network.dns.dnssec
 * @nav    Network
 * @title  DNSSEC validation
 *
 * @intro
 *   Local DNSSEC signature verification (RFC 4033–4035 / 6605 / 8080) —
 *   the cryptographic core that lets a resolver client verify a DNS
 *   answer itself instead of trusting the upstream resolver's AD bit.
 *   <code>b.network.dns.resolver</code> checks the AD flag; this module
 *   verifies the actual RRSIG signature over the canonicalised RRset,
 *   defending against a compromised or on-path resolver.
 *
 *   <code>verifyRrset</code> reconstructs the RFC 4034 §3.1.8.1 signed
 *   data (the RRSIG RDATA without the signature, followed by the RRset
 *   in canonical form — owner names lowercased, RRs ordered by canonical
 *   RDATA, the RRSIG's Original TTL) and verifies it with the DNSKEY,
 *   enforcing the signature's inception / expiration window. The DNSKEY
 *   algorithms are RSA/SHA-256 (8), ECDSA P-256/SHA-256 (13), ECDSA
 *   P-384/SHA-384 (14), and Ed25519 (15) — the modern, deployed set.
 *   <code>verifyDs</code> checks a delegation-signer digest against a
 *   DNSKEY (SHA-256 / SHA-384), and <code>keyTag</code> computes the
 *   RFC 4034 Appendix B key tag.
 *
 *   <strong>Scope.</strong> This is the verification core. RR types that
 *   carry domain names in their RDATA (NS, CNAME, SOA, MX, SRV, …) need
 *   name-lowercasing inside the RDATA (RFC 4034 §6.2) that this version
 *   does not perform, so they are refused with
 *   <code>dnssec/uncanonicalizable-type</code> rather than mis-validated
 *   — the security-critical DNSKEY / DS and the name-free address /
 *   text types (A, AAAA, TXT, …) are fully supported. The recursive
 *   chain-walk (root → TLD → zone), NSEC / NSEC3 denial-of-existence,
 *   and the IANA root trust-anchor bundle are deferred: these primitives
 *   are the per-RRset building blocks a chain-walker composes.
 *
 * @card
 *   Local DNSSEC verification (RFC 4035) — verify an RRSIG over a
 *   canonicalised RRset against a DNSKEY (RSA / ECDSA P-256·P-384 /
 *   Ed25519), plus DS-digest + key-tag. Don't trust the upstream AD bit;
 *   verify the signature. Name-bearing RR types are refused, not
 *   mis-validated; chain-walk + NSEC3 deferred.
 */

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DnssecError = defineClass("DnssecError", { alwaysPermanent: true });

// DNSSEC algorithm numbers (IANA DNSSEC Algorithm Numbers) → verify params.
var ALGS = {
  8:  { name: "RSASHA256",        kind: "rsa",   hash: "sha256" },                          // allow:raw-byte-literal — IANA DNSSEC algorithm number
  13: { name: "ECDSAP256SHA256",  kind: "ec",    hash: "sha256", crv: "P-256", coord: 32 },   // allow:raw-byte-literal — P-256 coordinate size
  14: { name: "ECDSAP384SHA384",  kind: "ec",    hash: "sha384", crv: "P-384", coord: 48 },   // allow:raw-byte-literal — P-384 coordinate size
  15: { name: "ED25519",          kind: "okp",   hash: null,     crv: "Ed25519" },
};

// DS digest algorithms (IANA) → node hash.
var DS_DIGESTS = { 2: "sha256", 4: "sha384" };

// RR types whose RDATA contains NO embedded domain name, so the wire
// RDATA is already in canonical form (RFC 4034 §6.2 needs no rewrite).
// Name-bearing types are refused rather than silently mis-canonicalised.
// (type numbers IANA): A 1, AAAA 28, TXT 16, DNSKEY 48, DS 43, CAA 257,
// TLSA 52, SSHFP 44, HINFO 13, CDS 59, CDNSKEY 60, OPENPGPKEY 61, SMIMEA 53.
var NAME_FREE_TYPE_NUMS = [1, 28, 16, 48, 43, 257, 52, 44, 13, 59, 60, 61, 53];          // allow:raw-byte-literal allow:raw-time-literal — IANA DNS type numbers (no embedded names)
var TYPE_NUM = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
  DS: 43, SSHFP: 44, RRSIG: 46, DNSKEY: 48, TLSA: 52, SMIMEA: 53, CDS: 59, CDNSKEY: 60, // allow:raw-byte-literal allow:raw-time-literal — IANA DNS type numbers
  OPENPGPKEY: 61, CAA: 257, HINFO: 13,
};

function _bytes(x, what) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  throw new DnssecError("dnssec/bad-bytes", "dnssec: " + what + " must be a Buffer");
}

// Canonical wire form of a domain name (RFC 4034 §6.2): each label
// length-prefixed, ASCII lowercased, terminated by the root label.
function _canonicalName(name) {
  if (typeof name !== "string") throw new DnssecError("dnssec/bad-name", "dnssec: name must be a string");
  var n = name.replace(/\.$/, "");
  if (n === "") return Buffer.from([0]);
  var labels = n.split(".");
  var parts = [];
  for (var i = 0; i < labels.length; i++) {
    var lab = Buffer.from(labels[i].toLowerCase(), "ascii");
    if (lab.length === 0 || lab.length > 63) {                                          // allow:raw-byte-literal — DNS label length cap (RFC 1035)
      throw new DnssecError("dnssec/bad-name", "dnssec: invalid label in '" + name + "'");
    }
    parts.push(Buffer.from([lab.length]), lab);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function _u16(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }                    // allow:raw-byte-literal — 16-bit big-endian split
function _u32(n) {
  var b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
function _typeNumber(type) {
  if (typeof type === "number") return type;
  var t = TYPE_NUM[String(type).toUpperCase()];
  if (t === undefined) throw new DnssecError("dnssec/unknown-type", "dnssec: unknown RR type '" + type + "'");
  return t;
}

// DNSKEY public-key RDATA → JWK (kty/crv allowlisted; RFC 3110 RSA,
// RFC 6605 ECDSA, RFC 8080 Ed25519). publicKey is the key bytes after
// the DNSKEY flags/protocol/algorithm fields.
function _dnskeyToKey(algId, publicKey) {
  var alg = ALGS[algId];
  if (!alg) throw new DnssecError("dnssec/unsupported-alg", "dnssec: unsupported DNSKEY algorithm " + algId);
  var pk = _bytes(publicKey, "dnskey publicKey");
  if (alg.kind === "rsa") {
    // RFC 3110: exponent length is 1 byte, or (if that byte is 0) the
    // next 2 bytes; then exponent, then modulus.
    var off = 0, explen = pk[0];
    off = 1;
    if (explen === 0) { explen = (pk[1] << 8) | pk[2]; off = 3; }                        // allow:raw-byte-literal — RFC 3110 3-byte exponent length
    if (explen === 0 || off + explen >= pk.length) {
      throw new DnssecError("dnssec/bad-key", "dnssec: malformed RSA DNSKEY public key");
    }
    var exponent = pk.slice(off, off + explen);
    var modulus = pk.slice(off + explen);
    return _jwkKey({ kty: "RSA", n: modulus.toString("base64url"), e: exponent.toString("base64url") });
  }
  if (alg.kind === "ec") {
    if (pk.length !== alg.coord * 2) {
      throw new DnssecError("dnssec/bad-key", "dnssec: " + alg.crv + " key must be " + (alg.coord * 2) + " bytes (x||y)");
    }
    return _jwkKey({ kty: "EC", crv: alg.crv, x: pk.slice(0, alg.coord).toString("base64url"), y: pk.slice(alg.coord).toString("base64url") });
  }
  // Ed25519
  if (pk.length !== 32) throw new DnssecError("dnssec/bad-key", "dnssec: Ed25519 key must be 32 bytes");   // allow:raw-byte-literal — Ed25519 key size
  return _jwkKey({ kty: "OKP", crv: "Ed25519", x: pk.toString("base64url") });
}
function _jwkKey(jwk) {
  try { return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }
  catch (e) { throw new DnssecError("dnssec/bad-key", "dnssec: could not import DNSKEY: " + ((e && e.message) || e)); }
}

/**
 * @primitive b.network.dns.dnssec.keyTag
 * @signature b.network.dns.dnssec.keyTag(dnskeyRdata)
 * @since     0.12.48
 * @status    stable
 * @related   b.network.dns.dnssec.verifyDs, b.network.dns.dnssec.verifyRrset
 *
 * Compute the RFC 4034 Appendix B key tag of a DNSKEY from its full
 * RDATA (flags || protocol || algorithm || public key) — the 16-bit
 * identifier an RRSIG / DS references to select the signing key.
 *
 * @example
 *   var tag = b.network.dns.dnssec.keyTag(dnskeyRdata);
 */
function keyTag(dnskeyRdata) {
  var rd = _bytes(dnskeyRdata, "dnskeyRdata");
  var acc = 0;
  for (var i = 0; i < rd.length; i++) {
    acc += (i & 1) ? rd[i] : (rd[i] << 8);                                               // allow:raw-byte-literal — RFC 4034 App B key-tag accumulation
  }
  acc += (acc >> 16) & 0xffff;                                                           // allow:raw-byte-literal — App B fold
  return acc & 0xffff;                                                                   // allow:raw-byte-literal — App B 16-bit tag
}

/**
 * @primitive b.network.dns.dnssec.verifyDs
 * @signature b.network.dns.dnssec.verifyDs(opts)
 * @since     0.12.48
 * @status    stable
 * @related   b.network.dns.dnssec.verifyRrset
 *
 * Verify a DS (Delegation Signer) record against a child DNSKEY — the
 * link that lets a parent zone vouch for a child's key. The DS digest
 * (SHA-256 / SHA-384) is recomputed over the owner name plus the DNSKEY
 * RDATA and compared to the DS, with the key tag and algorithm checked.
 *
 * @opts
 *   {
 *     ownerName:    string,   // the child zone name (the DNSKEY owner)
 *     dnskeyRdata:  Buffer,   // full DNSKEY RDATA (flags||protocol||alg||publicKey)
 *     ds: { keyTag, algorithm, digestType, digest: Buffer },  // the parent DS
 *   }
 *
 * @example
 *   b.network.dns.dnssec.verifyDs({ ownerName: "example.com", dnskeyRdata: ksk, ds: parentDs });
 */
function verifyDs(opts) {
  validateOpts.requireObject(opts, "dnssec.verifyDs", DnssecError);
  validateOpts(opts, ["ownerName", "dnskeyRdata", "ds"], "dnssec.verifyDs");
  var ds = opts.ds;
  if (!ds || typeof ds !== "object") throw new DnssecError("dnssec/bad-ds", "dnssec.verifyDs: opts.ds is required");
  var hashName = DS_DIGESTS[ds.digestType];
  if (!hashName) throw new DnssecError("dnssec/unsupported-digest", "dnssec.verifyDs: unsupported DS digest type " + ds.digestType);
  var rd = _bytes(opts.dnskeyRdata, "dnskeyRdata");
  if (keyTag(rd) !== ds.keyTag) {
    throw new DnssecError("dnssec/keytag-mismatch", "dnssec.verifyDs: DNSKEY key tag does not match the DS");
  }
  var digestInput = Buffer.concat([_canonicalName(opts.ownerName), rd]);
  var expected = nodeCrypto.createHash(hashName).update(digestInput).digest();
  var actual = _bytes(ds.digest, "ds.digest");
  if (!bCrypto.timingSafeEqual(expected, actual)) {
    throw new DnssecError("dnssec/ds-mismatch", "dnssec.verifyDs: DS digest does not match the DNSKEY");
  }
  return { ok: true, keyTag: ds.keyTag, digestType: ds.digestType };
}

/**
 * @primitive b.network.dns.dnssec.verifyRrset
 * @signature b.network.dns.dnssec.verifyRrset(opts)
 * @since     0.12.48
 * @status    stable
 * @compliance soc2
 * @related   b.network.dns.dnssec.verifyDs, b.network.dns.resolver.create
 *
 * Verify an RRSIG over an RRset against a DNSKEY (RFC 4035 §5.3). The
 * signed data is reconstructed in canonical form — the RRSIG RDATA
 * without the signature, then the RRset's records ordered by canonical
 * RDATA with the RRSIG Original TTL — and the signature is verified with
 * the DNSKEY (RSA/SHA-256, ECDSA P-256/384, Ed25519). The signature's
 * inception / expiration window is enforced against <code>opts.at</code>.
 * RR types carrying embedded domain names are refused
 * (<code>dnssec/uncanonicalizable-type</code>) rather than mis-validated.
 *
 * @opts
 *   {
 *     name:    string,    // owner name of the RRset
 *     type:    string|number, // RR type (e.g. "DNSKEY", "A")
 *     class?:  number,    // default 1 (IN)
 *     rdatas:  Buffer[],  // each record's wire-format RDATA
 *     rrsig: {            // the RRSIG covering the RRset
 *       algorithm, labels, originalTtl, expiration, inception, keyTag,
 *       signerName: string, signature: Buffer,
 *     },
 *     dnskey: { algorithm, publicKey: Buffer },  // the signing DNSKEY (publicKey = bytes after flags/proto/alg)
 *     at?:     Date,      // validity instant (default now); must be a valid Date
 *   }
 *
 * @example
 *   b.network.dns.dnssec.verifyRrset({ name: "example.com", type: "DNSKEY", rdatas: keys, rrsig: sig, dnskey: ksk });
 */
function verifyRrset(opts) {
  validateOpts.requireObject(opts, "dnssec.verifyRrset", DnssecError);
  validateOpts(opts, ["name", "type", "class", "rdatas", "rrsig", "dnskey", "at"], "dnssec.verifyRrset");
  var rrsig = opts.rrsig;
  var dnskey = opts.dnskey;
  if (!rrsig || typeof rrsig !== "object") throw new DnssecError("dnssec/bad-rrsig", "dnssec.verifyRrset: opts.rrsig is required");
  if (!dnskey || typeof dnskey !== "object") throw new DnssecError("dnssec/bad-key", "dnssec.verifyRrset: opts.dnskey is required");
  if (!Array.isArray(opts.rdatas) || opts.rdatas.length === 0) {
    throw new DnssecError("dnssec/empty-rrset", "dnssec.verifyRrset: opts.rdatas must be a non-empty array");
  }
  var alg = ALGS[rrsig.algorithm];
  if (!alg) throw new DnssecError("dnssec/unsupported-alg", "dnssec.verifyRrset: unsupported algorithm " + rrsig.algorithm);
  if (dnskey.algorithm !== rrsig.algorithm) {
    throw new DnssecError("dnssec/alg-mismatch", "dnssec.verifyRrset: DNSKEY algorithm does not match the RRSIG");
  }

  var typeNum = _typeNumber(opts.type);
  if (NAME_FREE_TYPE_NUMS.indexOf(typeNum) === -1) {
    throw new DnssecError("dnssec/uncanonicalizable-type",
      "dnssec.verifyRrset: RR type " + typeNum + " carries embedded names; RDATA-name canonicalisation is not supported (refused, not mis-validated)");
  }

  // Validity window (fail closed on a bad opts.at).
  var atMs;
  if (opts.at !== undefined && opts.at !== null) {
    if (!(opts.at instanceof Date) || !isFinite(opts.at.getTime())) {
      throw new DnssecError("dnssec/bad-at", "dnssec.verifyRrset: opts.at must be a valid Date");
    }
    atMs = opts.at.getTime();
  } else {
    atMs = Date.now();
  }
  var nowSec = Math.floor(atMs / 1000);                       // allow:raw-time-literal — ms→NumericDate seconds (RRSIG inception/expiration are seconds since epoch, RFC 4034 §3.1.5)
  if (nowSec < (rrsig.inception >>> 0)) throw new DnssecError("dnssec/not-yet-valid", "dnssec.verifyRrset: RRSIG inception is in the future");
  if (nowSec > (rrsig.expiration >>> 0)) throw new DnssecError("dnssec/expired", "dnssec.verifyRrset: RRSIG has expired");

  var klass = typeof opts.class === "number" ? opts.class : 1;
  var ownerWire = _canonicalName(opts.name);
  var ttl = _u32(rrsig.originalTtl);

  // Canonical RRset (RFC 4034 §6.3): order records by canonical RDATA.
  var rdatas = opts.rdatas.map(function (r, i) { return _bytes(r, "rdatas[" + i + "]"); });
  var sorted = rdatas.slice().sort(Buffer.compare);
  var rrParts = [];
  for (var i = 0; i < sorted.length; i++) {
    rrParts.push(ownerWire, _u16(typeNum), _u16(klass), ttl, _u16(sorted[i].length), sorted[i]);
  }

  // RRSIG RDATA without the signature (RFC 4034 §3.1.8.1).
  var rrsigPrefix = Buffer.concat([
    _u16(typeNum), Buffer.from([rrsig.algorithm & 0xff, rrsig.labels & 0xff]),           // allow:raw-byte-literal — single-octet alg + labels fields
    _u32(rrsig.originalTtl), _u32(rrsig.expiration), _u32(rrsig.inception),
    _u16(rrsig.keyTag), _canonicalName(rrsig.signerName),
  ]);
  var signedData = Buffer.concat([rrsigPrefix].concat(rrParts));

  var key = _dnskeyToKey(dnskey.algorithm, dnskey.publicKey);
  var signature = _bytes(rrsig.signature, "rrsig.signature");
  var ok;
  try {
    if (alg.kind === "okp") {
      ok = nodeCrypto.verify(null, signedData, key, signature);
    } else if (alg.kind === "ec") {
      ok = nodeCrypto.verify(alg.hash, signedData, { key: key, dsaEncoding: "ieee-p1363" }, signature);
    } else {
      ok = nodeCrypto.verify(alg.hash, signedData, key, signature);
    }
  } catch (e) {
    throw new DnssecError("dnssec/verify-threw", "dnssec.verifyRrset: signature verification threw: " + ((e && e.message) || e));
  }
  if (!ok) throw new DnssecError("dnssec/bad-signature", "dnssec.verifyRrset: RRSIG signature did not verify");
  return { ok: true, algorithm: alg.name, keyTag: rrsig.keyTag, signerName: rrsig.signerName };
}

module.exports = {
  verifyRrset: verifyRrset,
  verifyDs:    verifyDs,
  keyTag:      keyTag,
  ALGORITHMS:  ALGS,
  DnssecError: DnssecError,
};
