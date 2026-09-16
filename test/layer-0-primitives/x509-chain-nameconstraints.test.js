// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * X.509 nameConstraints enforcement (RFC 5280 §4.2.1.10 / §6.1.4) via
 * b.x509Chain.nameConstraintsSatisfied.
 *
 * node:crypto X509Certificate does not evaluate nameConstraints, and
 * checkIssued does not either, so a CA certificate that carries a
 * permittedSubtrees/excludedSubtrees constraint can vouch for a leaf whose
 * subjectAltName falls outside it. openssl rejects such a chain (error 47,
 * permitted/excluded subtree violation). These tests mint constrained chains
 * and prove the new primitive rejects a name outside the permitted set or
 * inside an excluded set, and accepts a name that satisfies the constraint,
 * with the constraint accumulating down the chain.
 */

var helpers = require("../helpers");
var check   = helpers.check;

var nodeCrypto = require("crypto");
var pki  = require("../../lib/vendor/blamejs-pki.cjs");
var x509Chain = require("../../lib/x509-chain");
var asn1 = require("../../lib/asn1-der");

// Build a root CA carrying a RAW nameConstraints extension value (bytes chosen
// by the caller, e.g. a malformed empty SEQUENCE that pki refuses to emit) and a
// leaf it issues. Returns node X509Certificate objects. Self-signed EC certs
// assembled with the in-tree DER writer + node:crypto signing.
function _rawChain(opts) {
  var ncValueDer = opts.rootNc || null;
  var leafSanDer = opts.leafSan || null;
  function _utc(d) { return asn1.writeNode(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z", "ascii")); }
  function _name(cn) { return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]); }
  var sigAlg = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]); // ecdsa-with-SHA256
  var now = new Date(), na = new Date(Date.now() + 3e10);
  var validity = asn1.writeSequence([_utc(now), _utc(na)]);
  function _cert(subjectName, issuerName, subjectKp, issuerKp, exts) {
    var spki = subjectKp.publicKey.export({ type: "spki", format: "der" });
    var children = [
      asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),
      asn1.writeInteger(Buffer.from([0x2a])), sigAlg, issuerName, validity, subjectName, spki,
    ];
    if (exts.length) children.push(asn1.writeContextExplicit(3, asn1.writeSequence(exts)));
    var tbs = asn1.writeSequence(children);
    var sig = nodeCrypto.sign("sha256", tbs, issuerKp.privateKey);
    return new nodeCrypto.X509Certificate(asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(sig, 0)]));
  }
  var rootKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var leafKp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var rootName = _name("Raw NC Root");
  var caBc = asn1.writeSequence([asn1.writeOid("2.5.29.19"), asn1.writeBoolean(true), asn1.writeOctetString(asn1.writeSequence([asn1.writeBoolean(true)]))]);
  var rootExts = [caBc];
  if (ncValueDer) rootExts.push(asn1.writeSequence([asn1.writeOid("2.5.29.30"), asn1.writeBoolean(true), asn1.writeOctetString(ncValueDer)]));
  var leafBc = asn1.writeSequence([asn1.writeOid("2.5.29.19"), asn1.writeBoolean(true), asn1.writeOctetString(asn1.writeSequence([]))]);
  var leafExts = [leafBc];
  if (leafSanDer) leafExts.push(asn1.writeSequence([asn1.writeOid("2.5.29.17"), asn1.writeOctetString(leafSanDer)]));
  if (opts.leafSan2) leafExts.push(asn1.writeSequence([asn1.writeOid("2.5.29.17"), asn1.writeOctetString(opts.leafSan2)]));
  var root = _cert(rootName, rootName, rootKp, rootKp, rootExts);
  var leaf = _cert(_name("raw-nc-leaf.example"), rootName, leafKp, rootKp, leafExts);
  return { root: root, leaf: leaf };
}

var ALG = { name: "ECDSA", namedCurve: "P-256" };

async function _spki(publicKey) {
  return Buffer.from(await pki.webcrypto.subtle.exportKey("spki", publicKey));
}

// Mint root -> intermediate(nameConstraints) -> leaf(subjectAltName), returning
// node X509Certificate objects leaf-first plus the root PEM. opts.constraints is
// the intermediate's nameConstraints ({permitted?, excluded?} arrays of
// GeneralName form objects); opts.leafSan is the leaf's subjectAltName array;
// opts.leafSubject overrides the leaf subject DN (for directoryName tests).
async function _mintConstrainedChain(opts) {
  opts = opts || {};
  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  var rootKeys = await pki.webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  var rootSpki = await _spki(rootKeys.publicKey);
  var rootPem = await pki.x509.sign({
    subject: opts.rootSubject || "NC Root CA", subjectPublicKey: rootSpki, serialNumber: "01",
    notBefore: now, notAfter: notAfter,
    extensions: Object.assign({
      basicConstraints: { cA: true, critical: true },
      keyUsage: ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    }, opts.rootConstraints ? { nameConstraints: opts.rootConstraints } : {}),
  }, { key: rootKeys.privateKey }, { pem: true });

  var intKeys = await pki.webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  var intSpki = await _spki(intKeys.publicKey);
  var intPem = await pki.x509.sign({
    subject: opts.intSubject || "NC Intermediate CA", subjectPublicKey: intSpki, serialNumber: "02",
    notBefore: now, notAfter: notAfter,
    extensions: Object.assign({
      basicConstraints: { cA: true, critical: true },
      keyUsage: ["keyCertSign"], keyUsageCritical: true,
    }, opts.constraints ? { nameConstraints: opts.constraints } : {}),
  }, { name: opts.rootSubject || "NC Root CA", publicKey: rootSpki, key: rootKeys.privateKey }, { pem: true });

  var leafKeys = await pki.webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  var leafSpki = await _spki(leafKeys.publicKey);
  var leafExts = { basicConstraints: { cA: false, critical: true }, keyUsage: ["digitalSignature"], keyUsageCritical: true };
  if (opts.leafSan) leafExts.subjectAltName = opts.leafSan;
  var leafPem = await pki.x509.sign({
    subject: opts.leafSubject || "nc-leaf.example", subjectPublicKey: leafSpki, serialNumber: "03",
    notBefore: now, notAfter: notAfter, extensions: leafExts,
  }, { name: opts.intSubject || "NC Intermediate CA", publicKey: intSpki, key: intKeys.privateKey }, { pem: true });

  function C(pem) { return new nodeCrypto.X509Certificate(pem); }
  return {
    leaf: C(leafPem), intermediate: C(intPem), root: C(rootPem),
    rootPem: rootPem,
    chain: [C(leafPem), C(intPem), C(rootPem)],
  };
}

async function run() {
  check("b.x509Chain.nameConstraintsSatisfied is exposed",
        typeof x509Chain.nameConstraintsSatisfied === "function");

  // FLAGSHIP FAIL-OPEN: an intermediate constrained to permitted dNSName
  // example.com issues a leaf whose SAN is evil.com. Every issuer link verifies,
  // but the leaf name is outside the permitted subtree → the chain must be rejected.
  var out = await _mintConstrainedChain({
    constraints: { permitted: [{ dNSName: "example.com" }] },
    leafSan: [{ dNSName: "evil.com" }],
  });
  check("dNSName permitted: a leaf SAN outside the permitted subtree is REJECTED",
        x509Chain.nameConstraintsSatisfied(out.chain) === false);

  // Within the permitted subtree (a subdomain) is accepted.
  var okSub = await _mintConstrainedChain({
    constraints: { permitted: [{ dNSName: "example.com" }] },
    leafSan: [{ dNSName: "host.example.com" }],
  });
  check("dNSName permitted: a subdomain within the permitted subtree is accepted",
        x509Chain.nameConstraintsSatisfied(okSub.chain) === true);

  // Exact match of the permitted base is accepted.
  var okExact = await _mintConstrainedChain({
    constraints: { permitted: [{ dNSName: "example.com" }] },
    leafSan: [{ dNSName: "example.com" }],
  });
  check("dNSName permitted: an exact match of the permitted base is accepted",
        x509Chain.nameConstraintsSatisfied(okExact.chain) === true);

  // Label-boundary: "notexample.com" is NOT within "example.com".
  var boundary = await _mintConstrainedChain({
    constraints: { permitted: [{ dNSName: "example.com" }] },
    leafSan: [{ dNSName: "notexample.com" }],
  });
  check("dNSName permitted: a non-label-boundary suffix (notexample.com) is REJECTED",
        x509Chain.nameConstraintsSatisfied(boundary.chain) === false);

  // Excluded subtree: a leaf within an excluded subtree is rejected even with no permitted set.
  var excl = await _mintConstrainedChain({
    constraints: { excluded: [{ dNSName: "bad.example.com" }] },
    leafSan: [{ dNSName: "host.bad.example.com" }],
  });
  check("dNSName excluded: a leaf within the excluded subtree is REJECTED",
        x509Chain.nameConstraintsSatisfied(excl.chain) === false);
  var exclOk = await _mintConstrainedChain({
    constraints: { excluded: [{ dNSName: "bad.example.com" }] },
    leafSan: [{ dNSName: "good.example.com" }],
  });
  check("dNSName excluded: a leaf outside the excluded subtree is accepted",
        x509Chain.nameConstraintsSatisfied(exclOk.chain) === true);

  // iPAddress constraints (address/mask CIDR). Base is addr||mask bytes.
  var ipBase = Buffer.from([10, 0, 0, 0, 255, 0, 0, 0]); // 10.0.0.0/8
  var ipIn = await _mintConstrainedChain({ constraints: { permitted: [{ iPAddress: ipBase }] }, leafSan: [{ iPAddress: "10.1.2.3" }] });
  check("iPAddress permitted: an address inside the CIDR is accepted",
        x509Chain.nameConstraintsSatisfied(ipIn.chain) === true);
  var ipOut = await _mintConstrainedChain({ constraints: { permitted: [{ iPAddress: ipBase }] }, leafSan: [{ iPAddress: "192.168.1.1" }] });
  check("iPAddress permitted: an address outside the CIDR is REJECTED",
        x509Chain.nameConstraintsSatisfied(ipOut.chain) === false);
  var ipExcl = await _mintConstrainedChain({ constraints: { excluded: [{ iPAddress: ipBase }] }, leafSan: [{ iPAddress: "10.9.9.9" }] });
  check("iPAddress excluded: an address inside the excluded CIDR is REJECTED",
        x509Chain.nameConstraintsSatisfied(ipExcl.chain) === false);

  // Restrictions apply only to names of the constrained type that are present:
  // a dNSName leaf under an iPAddress-only permitted constraint is unaffected.
  var mixedType = await _mintConstrainedChain({ constraints: { permitted: [{ iPAddress: ipBase }] }, leafSan: [{ dNSName: "anything.example" }] });
  check("a name type not covered by any permitted subtree is unconstrained",
        x509Chain.nameConstraintsSatisfied(mixedType.chain) === true);

  // FAIL CLOSED on a constraint subtree form this build does not evaluate
  // (rfc822Name / directoryName / URI): reject rather than silently ignore.
  var emailConstraint = await _mintConstrainedChain({ constraints: { permitted: [{ rfc822Name: "example.com" }] }, leafSan: [{ dNSName: "host.example.com" }] });
  check("fail-closed: a chain under an unevaluated constraint form (rfc822Name) is REJECTED",
        x509Chain.nameConstraintsSatisfied(emailConstraint.chain) === false);

  // Constraints accumulate: a root permits example.com, an intermediate narrows
  // to sub.example.com; a leaf outside the intermediate's subtree is rejected.
  var narrowed = await _mintConstrainedChain({
    rootConstraints: { permitted: [{ dNSName: "example.com" }] },
    constraints: { permitted: [{ dNSName: "sub.example.com" }] },
    leafSan: [{ dNSName: "host.example.com" }],
  });
  check("accumulation: a leaf outside a narrower intermediate subtree is REJECTED",
        x509Chain.nameConstraintsSatisfied(narrowed.chain) === false);
  var narrowedOk = await _mintConstrainedChain({
    rootConstraints: { permitted: [{ dNSName: "example.com" }] },
    constraints: { permitted: [{ dNSName: "sub.example.com" }] },
    leafSan: [{ dNSName: "host.sub.example.com" }],
  });
  check("accumulation: a leaf within both subtrees is accepted",
        x509Chain.nameConstraintsSatisfied(narrowedOk.chain) === true);

  // Consumer path: resolveChain (the DFS the token/message walkers route through)
  // must reject a chain that violates nameConstraints and accept one that satisfies them.
  var rcBad = x509Chain.resolveChain(out.leaf, [out.leaf, out.intermediate], [out.root]);
  check("resolveChain: a nameConstraints-violating chain is rejected (reason nameconstraint)",
        rcBad.ok === false && rcBad.reason === "nameconstraint");
  var rcOk = x509Chain.resolveChain(okSub.leaf, [okSub.leaf, okSub.intermediate], [okSub.root]);
  check("resolveChain: a nameConstraints-satisfying chain is accepted",
        rcOk.ok === true);

  // Leading-dot dNSName subtrees (subdomain-only): ".example.com" matches
  // host.example.com but NOT example.com itself.
  var dotExclSub = await _mintConstrainedChain({
    constraints: { excluded: [{ dNSName: ".example.com" }] },
    leafSan: [{ dNSName: "host.example.com" }],
  });
  check("leading-dot excluded: a subdomain within .example.com is REJECTED",
        x509Chain.nameConstraintsSatisfied(dotExclSub.chain) === false);
  var dotExclApex = await _mintConstrainedChain({
    constraints: { excluded: [{ dNSName: ".example.com" }] },
    leafSan: [{ dNSName: "example.com" }],
  });
  check("leading-dot excluded: the bare apex example.com is NOT within .example.com (accepted)",
        x509Chain.nameConstraintsSatisfied(dotExclApex.chain) === true);
  var dotPermSub = await _mintConstrainedChain({
    constraints: { permitted: [{ dNSName: ".example.com" }] },
    leafSan: [{ dNSName: "host.example.com" }],
  });
  check("leading-dot permitted: a subdomain within .example.com is accepted",
        x509Chain.nameConstraintsSatisfied(dotPermSub.chain) === true);
  var dotPermApex = await _mintConstrainedChain({
    constraints: { permitted: [{ dNSName: ".example.com" }] },
    leafSan: [{ dNSName: "example.com" }],
  });
  check("leading-dot permitted: the bare apex example.com is outside .example.com (REJECTED)",
        x509Chain.nameConstraintsSatisfied(dotPermApex.chain) === false);

  // An empty nameConstraints extension (30 00) is prohibited by RFC 5280
  // §4.2.1.10 (at least one of permitted/excluded MUST be present). The critical
  // extension is malformed → fail closed rather than treat the CA as
  // unconstrained. pki refuses to emit it, so the cert is hand-assembled.
  var emptyNc = _rawChain({ rootNc: asn1.writeSequence([]) });
  check("fail-closed: an empty nameConstraints extension is rejected (nameConstraintsSatisfied)",
        x509Chain.nameConstraintsSatisfied([emptyNc.leaf, emptyNc.root]) === false);
  var emptyNcRc = x509Chain.resolveChain(emptyNc.leaf, [emptyNc.leaf], [emptyNc.root]);
  check("fail-closed: resolveChain rejects a chain whose CA carries an empty nameConstraints",
        emptyNcRc.ok === false && emptyNcRc.reason === "nameconstraint");

  // A malformed subjectAltName (a valid dNSName followed by a truncated
  // GeneralName) must not be treated as an absent SAN under an active
  // constraint: the names cannot be enumerated, so the chain fails closed.
  var permitExample = asn1.writeSequence([
    asn1.writeContextImplicit(0, asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("example.com", "latin1"))]), { constructed: true }),
  ]);
  var validGn = asn1.writeNode(0x82, Buffer.from("evil.com", "latin1"));
  var truncatedGn = Buffer.from([0x82, 0x05, 0x65, 0x76]); // [2] dNSName claims 5 bytes, only 2 present
  var sanContent = Buffer.concat([validGn, truncatedGn]);
  var malformedSan = Buffer.concat([Buffer.from([0x30, sanContent.length]), sanContent]);
  var badSan = _rawChain({ rootNc: permitExample, leafSan: malformedSan });
  check("fail-closed: a malformed SAN under an active permitted constraint is rejected (nameConstraintsSatisfied)",
        x509Chain.nameConstraintsSatisfied([badSan.leaf, badSan.root]) === false);
  // Reproduce the S/MIME path: its issuance predicate verifies the signature
  // without node's checkIssued (which rejects this malformed leaf on its own), so
  // nameConstraints is the only defense that must still reject the malformed SAN.
  var smimeIssued = function (issuer, subject) {
    try { return subject.issuer === issuer.subject && x509Chain.isCaCert(issuer) && subject.verify(issuer.publicKey); }
    catch (_e) { return false; }
  };
  var badSanRc = x509Chain.resolveChain(badSan.leaf, [badSan.leaf], [badSan.root], { issued: smimeIssued });
  check("fail-closed: resolveChain (S/MIME predicate) rejects a leaf with a malformed SAN under a permitted constraint",
        badSanRc.ok === false && badSanRc.reason === "nameconstraint");

  // A malformed iPAddress CONSTRAINT base (a four-byte value instead of the
  // eight-byte address+mask) must fail closed, not silently disable the subtree.
  var badIpExcluded = asn1.writeSequence([
    asn1.writeContextImplicit(1, asn1.writeSequence([asn1.writeNode(0x87, Buffer.from([10, 0, 0, 0]))]), { constructed: true }),
  ]);
  var leafIpSan = asn1.writeSequence([asn1.writeNode(0x87, Buffer.from([10, 1, 2, 3]))]);
  var badIp = _rawChain({ rootNc: badIpExcluded, leafSan: leafIpSan });
  check("fail-closed: a malformed iPAddress constraint base is rejected (nameConstraintsSatisfied)",
        x509Chain.nameConstraintsSatisfied([badIp.leaf, badIp.root]) === false);
  var badIpRc = x509Chain.resolveChain(badIp.leaf, [badIp.leaf], [badIp.root], { issued: smimeIssued });
  check("fail-closed: resolveChain (S/MIME predicate) rejects a malformed iPAddress constraint base",
        badIpRc.ok === false && badIpRc.reason === "nameconstraint");

  // Trailing bytes after the SAN or nameConstraints SEQUENCE (a parser
  // differential: our parser would see one name, another parser a second) fail
  // closed. The valid name alone would otherwise be permitted.
  var permittedName = asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("host.example.com", "latin1"))]);
  var sanTrail = _rawChain({ rootNc: permitExample, leafSan: Buffer.concat([permittedName, Buffer.from([0x00])]) });
  var sanTrailRc = x509Chain.resolveChain(sanTrail.leaf, [sanTrail.leaf], [sanTrail.root], { issued: smimeIssued });
  check("fail-closed: trailing bytes after the SAN SEQUENCE are rejected",
        sanTrailRc.ok === false && sanTrailRc.reason === "nameconstraint");
  var ncTrail = _rawChain({ rootNc: Buffer.concat([permitExample, Buffer.from([0x00])]), leafSan: permittedName });
  var ncTrailRc = x509Chain.resolveChain(ncTrail.leaf, [ncTrail.leaf], [ncTrail.root], { issued: smimeIssued });
  check("fail-closed: trailing bytes after the nameConstraints SEQUENCE are rejected",
        ncTrailRc.ok === false && ncTrailRc.reason === "nameconstraint");

  // A malformed GeneralName encoding (a UNIVERSAL IA5String where a
  // context-specific [2] dNSName is required) must fail closed, not be skipped
  // as an absent name — a lax parser could read it as evil.com.
  var universalIa5 = asn1.writeSequence([asn1.writeNode(0x16, Buffer.from("evil.com", "latin1"))]);
  var badGn = _rawChain({ rootNc: permitExample, leafSan: universalIa5 });
  var badGnRc = x509Chain.resolveChain(badGn.leaf, [badGn.leaf], [badGn.root], { issued: smimeIssued });
  check("fail-closed: a universal-tagged GeneralName in the SAN is rejected",
        badGnRc.ok === false && badGnRc.reason === "nameconstraint");

  // Duplicate (or out-of-order) permittedSubtrees/excludedSubtrees fields are a
  // DER violation and must fail closed, not let the second field overwrite the
  // first (which would silently drop the earlier restriction).
  function _permittedDns(name) {
    return asn1.writeContextImplicit(0, asn1.writeSequence([asn1.writeNode(0x82, Buffer.from(name, "latin1"))]), { constructed: true });
  }
  var dupNc = asn1.writeSequence([_permittedDns("example.com"), _permittedDns("evil.com")]);
  var dup = _rawChain({ rootNc: dupNc, leafSan: asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("evil.com", "latin1"))]) });
  check("fail-closed: duplicate permittedSubtrees fields are rejected (nameConstraintsSatisfied)",
        x509Chain.nameConstraintsSatisfied([dup.leaf, dup.root]) === false);
  // Through resolveChain the malformed-NC root is refused (on node 24/26 it also
  // marks the CA ca:false, so the issuance predicate rejects it first); either
  // way the chain fails closed.
  var dupRc = x509Chain.resolveChain(dup.leaf, [dup.leaf], [dup.root], { issued: smimeIssued });
  check("fail-closed: resolveChain rejects a chain whose CA has duplicate nameConstraints fields",
        dupRc.ok === false);

  // A SAN whose outer wrapper is a universal PRIMITIVE tag 16 (0x10) rather than
  // a constructed SEQUENCE (0x30) is malformed: the tag number alone is not
  // enough, the class and constructed bit must match. Fails closed.
  var validSanSeq = asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("host.example.com", "latin1"))]);
  var primitiveWrapper = Buffer.concat([Buffer.from([0x10]), validSanSeq.slice(1)]);
  var badWrap = _rawChain({ rootNc: permitExample, leafSan: primitiveWrapper });
  var badWrapRc = x509Chain.resolveChain(badWrap.leaf, [badWrap.leaf], [badWrap.root], { issued: smimeIssued });
  check("fail-closed: a SAN with a primitive (non-constructed) SEQUENCE wrapper is rejected",
        badWrapRc.ok === false && badWrapRc.reason === "nameconstraint");

  // Duplicate subjectAltName extensions are invalid (RFC 5280 §4.2): a parser
  // that reads only the first would miss a forbidden name in the second. Fail
  // closed rather than evaluate only the first SAN.
  var firstSan = asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("host.example.com", "latin1"))]);
  var secondSan = asn1.writeSequence([asn1.writeNode(0x82, Buffer.from("evil.com", "latin1"))]);
  var dupSan = _rawChain({ rootNc: permitExample, leafSan: firstSan, leafSan2: secondSan });
  check("fail-closed: duplicate SAN extensions are rejected (nameConstraintsSatisfied)",
        x509Chain.nameConstraintsSatisfied([dupSan.leaf, dupSan.root]) === false);
  var dupSanRc = x509Chain.resolveChain(dupSan.leaf, [dupSan.leaf], [dupSan.root], { issued: smimeIssued });
  check("fail-closed: resolveChain (S/MIME predicate) rejects a leaf with duplicate SAN extensions",
        dupSanRc.ok === false && dupSanRc.reason === "nameconstraint");

  // No constraints anywhere → accepted.
  var none = await _mintConstrainedChain({ leafSan: [{ dNSName: "anything.example" }] });
  check("no nameConstraints in the chain → accepted",
        x509Chain.nameConstraintsSatisfied(none.chain) === true);

  // Malformed / degenerate inputs fail closed.
  check("fail-closed: non-array input", x509Chain.nameConstraintsSatisfied(null) === false);
  check("fail-closed: a null chain entry", x509Chain.nameConstraintsSatisfied([null, none.chain[1]]) === false);
  check("single valid cert with no constraints is accepted", x509Chain.nameConstraintsSatisfied([none.chain[0]]) === true);

  console.log("OK — x509 nameConstraints enforcement (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
