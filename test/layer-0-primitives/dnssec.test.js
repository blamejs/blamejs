"use strict";
/**
 * Layer 0 — b.network.dns.dnssec (local DNSSEC RRSIG verification).
 * The oracles are REAL captured DNSKEY responses (Cloudflare DoH,
 * application/dns-message) for an ECDSA-P256 zone (cloudflare.com) and
 * an RSA/SHA-256 zone (verisign.com): a byte off in the RFC 4034
 * canonicalisation would fail these real-world signatures. Verified at a
 * fixed instant inside each RRSIG's window so the fixture never expires.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

// Real `cloudflare.com` DNSKEY response (ECDSA P-256 / alg 13), captured
// via Cloudflare DoH with the DO bit set.
var CF_HEX = "000081a000010003000000010a636c6f7564666c61726503636f6d0000300001c00c003000010000071200440100030da09311112cf9138818cd2feae970ebbd4d6a30f6088c25b325a39abbc5cd1197aa098283e5aaf421177c2aa5d714992a9957d1bcc18f98cd71f1f1806b65e148c00c003000010000071200440101030d99db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19c00c002e000100000712006200300d0200000e106a604d3e6a0fe1be09430a636c6f7564666c61726503636f6d008a40d46e9ff1d7eae7a3824de100af4eba33c5cc88751c29fb7bf1a931d68ab1d25c19c8be0f06da464aebaad3f171be9ed92e20ae1b1bf25e54cc18939a2a5e00002904d0000080000000";
// Real `verisign.com` DNSKEY response (RSA/SHA-256 / alg 8).
var VS_HEX = "000081a0000100040000000108766572697369676e03636f6d0000300001c00c0030000100000cb900880100030803010001a24a87ea79dcc74adda5bad2b0ad3e5514b06c30dd14dcfe1ef3503e1591ccd67a486bf4d87e496c9c5f7009f6796eb54324157d5baa5815063816323bd2f1d2846d278c34c551cd4cf67c1adf21427836603e37c4230bc47ce59845fb697f53471a824be691e683580b92020f12c7a8efeb02f12fc475dbdeca65a0bb0a4f6fc00c0030000100000cb900880100030803010001cc288a535db6a1b542355d84ad07d77cd1729f6eb191b24698becb69ec43aaddbc1714102fd9a8745683d211a33bc88103e96a893e83cff7d27bce7cfeafc6ac2b3b85d0f95e2952d8c413a54aaeee378701f8627805ac97a778a0cd323ce1585139a3a84a9e5a28850ed427e8038fd2f0600f96e0188f46f33acede7811d711c00c0030000100000cb901080101030803010001bfb6a7aca1ef6f910e6dc358935f7132dd3a6fc716550739861b28f4c06ab0e6a4d8082bc7615fa898ed12594cb03e8c89d918d3c2c0d1036bfeae7b73f831ac49634c46cdb3d0c307dd53298f32c52fc16764729b133c105a4ec701ba2a3fbbb60ee6cf9c21dcc0ffbb270e3bc5e6bbf4cf1d07d1b00f50655c5d8e7724f951b3ac69d748265351aa014269ffd31678248ce15168aed3fcfbb1a32704743d76b15fc1abdb157c17b3d7deee5a6742019c32ee87a9bce449281122f586964d3f23cd502fbbb2c0504611876c50ca780ea958313dc9f7dec485aa90cd15bf42a66d80da99df2c46c3974ead4f88332a810b83d6e2a416d7ee8318f3c4c671eaa3c00c002e000100000cb901200030080200000e106a3b146f6a13876fd7a408766572697369676e03636f6d0075ae4e787092f2120d8592cf56d3cd87f06813e38aadd90111ba7e656e90ee1c969591cda2ed4838db2648a68326fa04cbd3886ff2fd48f954284bff78459c8a78c4ecb8b2462f0bd1636555dd96b1e83f7cf322d1a4806480eef57e16b65cf5d2229184cab0c573f30a16f5af94b4cd15c05a04c62cd2ca8afc2f39c6067ec2fed95cc044f88f4a746388de20fe58decccda4b1cbc50d8f011cd56055c56c375464b9999e3e04d6a7180ca5fce5801b445cfc9f33b6fdac4f5c9d9714deaa77420ee4f147f1fefb63187230cfb93c2a3c218130c707fb42dfb4d445a33197ebfbf00087d1012f2dc0f4b29857908a2de33aef8ebbcc326cf4e1ef60181cf82a00002904d0000080000000";

function _rdName(buf, off) {
  var ls = [], jumped = false, end = off;
  for (;;) {
    var len = buf[off];
    if (len === 0) { off++; if (!jumped) end = off; break; }
    if ((len & 0xc0) === 0xc0) { if (!jumped) end = off + 2; off = ((len & 0x3f) << 8) | buf[off + 1]; jumped = true; continue; }
    off++; ls.push(buf.slice(off, off + len).toString("ascii")); off += len;
  }
  return { name: ls.join(".") + (ls.length ? "." : ""), end: end };
}

// Parse a DNSKEY DoH response → { keys: [{rdata, alg, pubkey}], rrsig }.
function _parse(hex) {
  var buf = Buffer.from(hex, "hex");
  var qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6), off = 12;
  for (var q = 0; q < qd; q++) off = _rdName(buf, off).end + 4;
  var keys = [], rrsig = null;
  for (var i = 0; i < an; i++) {
    off = _rdName(buf, off).end;
    var type = buf.readUInt16BE(off), rdlen = buf.readUInt16BE(off + 8);
    off += 10;
    var rd = buf.slice(off, off + rdlen); off += rdlen;
    if (type === 48) keys.push({ rdata: rd, alg: rd[3], pubkey: rd.slice(4) });
    else if (type === 46) {
      var sn = _rdName(rd, 18);
      rrsig = { algorithm: rd[2], labels: rd[3], originalTtl: rd.readUInt32BE(4), expiration: rd.readUInt32BE(8), inception: rd.readUInt32BE(12), keyTag: rd.readUInt16BE(16), signerName: sn.name, signature: rd.slice(sn.end) };
    }
  }
  return { keys: keys, rrsig: rrsig };
}

function _vector(hex, zone) {
  var p = _parse(hex);
  var ksk = p.keys.find(function (k) { return b.network.dns.dnssec.keyTag(k.rdata) === p.rrsig.keyTag; });
  return { zone: zone, keys: p.keys, rrsig: p.rrsig, ksk: ksk, at: new Date(p.rrsig.inception * 1000 + 1000) };
}

function testSurface() {
  check("b.network.dns.dnssec.verifyRrset is a function", typeof b.network.dns.dnssec.verifyRrset === "function");
  check("b.network.dns.dnssec.verifyDs is a function", typeof b.network.dns.dnssec.verifyDs === "function");
  check("b.network.dns.dnssec.keyTag is a function", typeof b.network.dns.dnssec.keyTag === "function");
}

function testRealVectors() {
  var cf = _vector(CF_HEX, "cloudflare.com");
  check("keyTag computes the real RRSIG key tag (ECDSA)", cf.ksk !== undefined);
  var ecOut = b.network.dns.dnssec.verifyRrset({ name: cf.zone, type: "DNSKEY", rdatas: cf.keys.map(function (k) { return k.rdata; }), rrsig: cf.rrsig, dnskey: { algorithm: cf.ksk.alg, publicKey: cf.ksk.pubkey }, at: cf.at });
  check("verifyRrset: real cloudflare.com DNSKEY self-sig verifies (ECDSAP256SHA256)", ecOut.ok && ecOut.algorithm === "ECDSAP256SHA256");

  var vs = _vector(VS_HEX, "verisign.com");
  check("keyTag computes the real RRSIG key tag (RSA)", vs.ksk !== undefined);
  var rsaOut = b.network.dns.dnssec.verifyRrset({ name: vs.zone, type: "DNSKEY", rdatas: vs.keys.map(function (k) { return k.rdata; }), rrsig: vs.rrsig, dnskey: { algorithm: vs.ksk.alg, publicKey: vs.ksk.pubkey }, at: vs.at });
  check("verifyRrset: real verisign.com DNSKEY self-sig verifies (RSASHA256)", rsaOut.ok && rsaOut.algorithm === "RSASHA256");
}

function testRefusals() {
  var cf = _vector(CF_HEX, "cloudflare.com");
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  var base = { name: cf.zone, type: "DNSKEY", rrsig: cf.rrsig, dnskey: { algorithm: cf.ksk.alg, publicKey: cf.ksk.pubkey }, at: cf.at };
  function withRdatas(rd) { return Object.assign({}, base, { rdatas: rd }); }

  var tampered = cf.keys.map(function (k) { return Buffer.from(k.rdata); });
  tampered[0][tampered[0].length - 1] ^= 0xff;
  check("verifyRrset: tampered RRset refused", code(function () { b.network.dns.dnssec.verifyRrset(withRdatas(tampered)); }) === "dnssec/bad-signature");

  var rd = cf.keys.map(function (k) { return k.rdata; });
  check("verifyRrset: expired RRSIG refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, at: new Date((cf.rrsig.expiration + 60) * 1000) })); }) === "dnssec/expired");
  check("verifyRrset: not-yet-valid RRSIG refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, at: new Date((cf.rrsig.inception - 60) * 1000) })); }) === "dnssec/not-yet-valid");
  check("verifyRrset: invalid opts.at refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, at: new Date("nope") })); }) === "dnssec/bad-at");
  check("verifyRrset: name-bearing RR type refused (not mis-validated)", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { type: "NS", rdatas: rd })); }) === "dnssec/uncanonicalizable-type");
  check("verifyRrset: DNSKEY/RRSIG algorithm mismatch refused", code(function () { b.network.dns.dnssec.verifyRrset(Object.assign({}, base, { rdatas: rd, dnskey: { algorithm: 8, publicKey: cf.ksk.pubkey } })); }) === "dnssec/alg-mismatch");
}

function testVerifyDs() {
  var cf = _vector(CF_HEX, "cloudflare.com");
  var nodeCrypto = require("node:crypto");
  // Build the SHA-256 DS digest over (canonical owner name || DNSKEY rdata),
  // then confirm verifyDs accepts it and rejects a tampered digest / key tag.
  function canonName(name) {
    var n = name.replace(/\.$/, ""), parts = [];
    n.split(".").forEach(function (l) { var b2 = Buffer.from(l.toLowerCase(), "ascii"); parts.push(Buffer.from([b2.length]), b2); });
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
  }
  var tag = b.network.dns.dnssec.keyTag(cf.ksk.rdata);
  var digest = nodeCrypto.createHash("sha256").update(Buffer.concat([canonName("cloudflare.com"), cf.ksk.rdata])).digest();
  var ds = { keyTag: tag, algorithm: cf.ksk.alg, digestType: 2, digest: digest };
  check("verifyDs: matching DS accepted", b.network.dns.dnssec.verifyDs({ ownerName: "cloudflare.com", dnskeyRdata: cf.ksk.rdata, ds: ds }).ok === true);

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  var badDigest = Buffer.from(digest); badDigest[0] ^= 0xff;
  check("verifyDs: tampered digest refused", code(function () { b.network.dns.dnssec.verifyDs({ ownerName: "cloudflare.com", dnskeyRdata: cf.ksk.rdata, ds: Object.assign({}, ds, { digest: badDigest }) }); }) === "dnssec/ds-mismatch");
  check("verifyDs: key-tag mismatch refused", code(function () { b.network.dns.dnssec.verifyDs({ ownerName: "cloudflare.com", dnskeyRdata: cf.ksk.rdata, ds: Object.assign({}, ds, { keyTag: (tag + 1) & 0xffff }) }); }) === "dnssec/keytag-mismatch");
}

// --- Denial of existence (NSEC / NSEC3) ---

var B32H = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
function b32hDecode(s) {
  s = s.toUpperCase();
  var bits = 0, val = 0, out = [];
  for (var i = 0; i < s.length; i++) { val = (val << 5) | B32H.indexOf(s[i]); bits += 5; if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); } }
  return Buffer.from(out);
}
var TY = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, RRSIG: 46, DNSKEY: 48, NSEC3PARAM: 51, CAA: 257, SRV: 33, DS: 43 };
function encodeBitmap(names) {
  if (!names.length) return Buffer.alloc(0);
  var byWin = {};
  names.forEach(function (nm) { var t = TY[nm]; (byWin[t >> 8] = byWin[t >> 8] || {})[t & 0xff] = 1; });
  var parts = [];
  Object.keys(byWin).map(Number).sort(function (a, c) { return a - c; }).forEach(function (w) {
    var bitsSet = Object.keys(byWin[w]).map(Number);
    var len = (Math.max.apply(null, bitsSet) >> 3) + 1, bm = Buffer.alloc(len);
    bitsSet.forEach(function (bit) { bm[bit >> 3] |= 0x80 >> (bit & 7); });
    parts.push(Buffer.from([w, len]), bm);
  });
  return Buffer.concat(parts);
}
function nsec3Rdata(opts) {
  var salt = opts.salt || Buffer.alloc(0);
  var next = Buffer.isBuffer(opts.next) ? opts.next : b32hDecode(opts.next);
  return Buffer.concat([
    Buffer.from([opts.hashAlg === undefined ? 1 : opts.hashAlg, opts.flags || 0, (opts.iterations >> 8) & 0xff, opts.iterations & 0xff, salt.length]),
    salt, Buffer.from([next.length]), next, encodeBitmap(opts.types || []),
  ]);
}
function nsecRdata(nextName, types) {
  var labels = nextName.replace(/\.$/, "").split(".");
  var parts = [];
  labels.forEach(function (l) { var bb = Buffer.from(l, "ascii"); parts.push(Buffer.from([bb.length]), bb); });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts.concat([encodeBitmap(types)]));
}
function bufInc(buf, delta) { var b2 = Buffer.from(buf); b2[b2.length - 1] = (b2[b2.length - 1] + delta) & 0xff; return b2; }

// Real `iana.org` NXDOMAIN proof (NSEC3, SHA-1, 0 iterations, empty salt),
// captured via Cloudflare DoH for nonexistent-blamejs-test-xyz.iana.org.
var IANA_NSEC3 = [
  { owner: "uqk2hjod270o42j2v1hoi7qtr945lhmb.iana.org", next: "VAVBTBDJ8O7H3CJCP1HL1CDPRTFQP46L", types: [] },
  { owner: "mvnqhoigoa305s1i78hp6cdv5n7lcutc.iana.org", next: "NGJOKE6KAKN5BC83M0IAPQVRBAJKQI3M", types: ["A", "NS", "SOA", "MX", "TXT", "AAAA", "RRSIG", "DNSKEY", "NSEC3PARAM", "CAA"] },
  { owner: "0d5cbi611aogl6kk8jjsopfic6dcb42t.iana.org", next: "26CS5JG5RASD1SS5VNTJ9PSC7FDVQIEO", types: ["CNAME", "RRSIG"] },
];
function ianaRecords() {
  return IANA_NSEC3.map(function (r) { return { owner: r.owner, rdata: nsec3Rdata({ iterations: 0, next: r.next, types: r.types }) }; });
}

function testNsec3Real() {
  // The NSEC3 hash of the apex equals the real apex owner label byte-exact.
  var h = b.network.dns.dnssec.nsec3Hash("iana.org", { salt: Buffer.alloc(0), iterations: 0 });
  check("nsec3Hash: matches the real iana.org apex owner label", Buffer.compare(h, b32hDecode("MVNQHOIGOA305S1I78HP6CDV5N7LCUTC")) === 0);

  var out = b.network.dns.dnssec.verifyDenial({ qname: "nonexistent-blamejs-test-xyz.iana.org", proof: "nxdomain", zone: "iana.org", nsec3: ianaRecords() });
  check("verifyDenial: real iana.org NXDOMAIN proven (NSEC3)", out.ok && out.proof === "nxdomain" && out.mechanism === "nsec3" && out.closestEncloser === "iana.org." && out.optOut === false);

  // Apex NODATA: the apex NSEC3 matches iana.org; a type absent from its
  // bitmap is proven NODATA, a type present is refused.
  var nodata = b.network.dns.dnssec.verifyDenial({ qname: "iana.org", qtype: "SRV", proof: "nodata", zone: "iana.org", nsec3: ianaRecords() });
  check("verifyDenial: real iana.org NODATA for absent type proven", nodata.ok && nodata.proof === "nodata" && nodata.matched === true);

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: NODATA refused when type IS present", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "iana.org", qtype: "A", proof: "nodata", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/denial-not-proven");
  // Removing the next-closer cover breaks the NXDOMAIN proof.
  check("verifyDenial: NXDOMAIN refused without a covering NSEC3", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "nonexistent-blamejs-test-xyz.iana.org", proof: "nxdomain", zone: "iana.org", nsec3: [ianaRecords()[1]] }); }) === "dnssec/denial-not-proven");
}

function testNsec3Caps() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  // Iterations beyond the cap are refused (iterated-SHA-1 DoS bound).
  var heavy = [{ owner: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.x", rdata: nsec3Rdata({ iterations: 9999, next: b32hDecode("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") }) }];
  check("verifyDenial: excessive NSEC3 iterations refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "q.x", proof: "nxdomain", zone: "x", nsec3: heavy }); }) === "dnssec/nsec3-iterations-excessive");
  // Unsupported hash algorithm refused.
  var badHash = [{ owner: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.x", rdata: nsec3Rdata({ hashAlg: 2, iterations: 0, next: b32hDecode("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") }) }];
  check("verifyDenial: unsupported NSEC3 hash algorithm refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "q.x", proof: "nxdomain", zone: "x", nsec3: badHash }); }) === "dnssec/unsupported-nsec3-hash");
}

function testNsec3OptOut() {
  // Construct an Opt-Out NXDOMAIN: matching apex + opt-out next-closer
  // cover + covered wildcard, using real hashes of chosen names.
  var salt = Buffer.alloc(0);
  function H(n) { return b.network.dns.dnssec.nsec3Hash(n, { salt: salt, iterations: 0 }); }
  var hT = H("test"), hX = H("x.test"), hW = H("*.test");
  function b32hEncode(buf) {
    var bits = 0, val = 0, out = "";
    for (var i = 0; i < buf.length; i++) { val = (val << 8) | buf[i]; bits += 8; while (bits >= 5) { bits -= 5; out += B32H[(val >> bits) & 31]; } }
    if (bits > 0) out += B32H[(val << (5 - bits)) & 31];
    return out;
  }
  var recs = [
    { owner: b32hEncode(hT) + ".test", rdata: nsec3Rdata({ flags: 0, iterations: 0, next: bufInc(hT, 1), types: ["NS", "SOA"] }) },
    { owner: b32hEncode(bufInc(hX, -1)) + ".test", rdata: nsec3Rdata({ flags: 1, iterations: 0, next: bufInc(hX, 1) }) },
    { owner: b32hEncode(bufInc(hW, -1)) + ".test", rdata: nsec3Rdata({ flags: 0, iterations: 0, next: bufInc(hW, 1) }) },
  ];
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: Opt-Out NXDOMAIN refused by default", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.test", proof: "nxdomain", zone: "test", nsec3: recs }); }) === "dnssec/denial-opt-out");
  var out = b.network.dns.dnssec.verifyDenial({ qname: "x.test", proof: "nxdomain", zone: "test", nsec3: recs, allowOptOut: true });
  check("verifyDenial: Opt-Out NXDOMAIN accepted with allowOptOut", out.ok && out.optOut === true);
}

function testNsec() {
  // Synthetic NSEC zone: apex + one name, both with bitmaps.
  var recs = [
    { owner: "example.com", rdata: nsecRdata("a.example.com", ["A", "NS", "SOA", "RRSIG", "DNSKEY"]) },
    { owner: "a.example.com", rdata: nsecRdata("example.com", ["A", "RRSIG"]) },
  ];
  var nx = b.network.dns.dnssec.verifyDenial({ qname: "b.example.com", proof: "nxdomain", zone: "example.com", nsec: recs });
  check("verifyDenial: NSEC NXDOMAIN proven (covering + wildcard)", nx.ok && nx.mechanism === "nsec" && nx.closestEncloser === "example.com.");

  var nd = b.network.dns.dnssec.verifyDenial({ qname: "example.com", qtype: "MX", proof: "nodata", zone: "example.com", nsec: recs });
  check("verifyDenial: NSEC NODATA proven for absent type", nd.ok && nd.matched === true);

  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: NSEC NODATA refused when type present", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "example.com", qtype: "A", proof: "nodata", zone: "example.com", nsec: recs }); }) === "dnssec/denial-not-proven");
}

function testDenialArgs() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("verifyDenial: bad proof value refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.iana.org", proof: "maybe", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/bad-arg");
  check("verifyDenial: zone not a suffix of qname refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.example.org", proof: "nxdomain", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/bad-arg");
  check("verifyDenial: both nsec and nsec3 supplied refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "x.iana.org", proof: "nxdomain", zone: "iana.org", nsec3: ianaRecords(), nsec: [{ owner: "iana.org", rdata: nsecRdata("a.iana.org", []) }] }); }) === "dnssec/bad-arg");
  check("verifyDenial: nodata without qtype refused", code(function () { b.network.dns.dnssec.verifyDenial({ qname: "iana.org", proof: "nodata", zone: "iana.org", nsec3: ianaRecords() }); }) === "dnssec/bad-arg");
}

async function run() {
  testSurface();
  testRealVectors();
  testRefusals();
  testVerifyDs();
  testNsec3Real();
  testNsec3Caps();
  testNsec3OptOut();
  testNsec();
  testDenialArgs();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[dnssec] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
