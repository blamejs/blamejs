// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Distinguished-name equality via b.x509Chain.canonicalNameKey.
 *
 * RFC 5280 §7.1 compares PrintableString and UTF8String attributes after
 * normalization, so one name encoded two ways is one name. Comparing the raw
 * DER instead refuses a certificate whose issuer a SignerInfo names in the
 * other string type, which is a valid envelope rejected.
 *
 * The null return is its own hazard: two unparseable nodes both key to null, so
 * a caller that compares keys without checking for null would read "equal" from
 * two names it could not read at all.
 */

var helpers = require("../helpers");
var check   = helpers.check;

var x509Chain = require("../../lib/x509-chain");
var asn1      = require("../../lib/asn1-der");

var OID_CN = "2.5.4.3";
var OID_O  = "2.5.4.10";

// A Name node: SEQUENCE OF RelativeDistinguishedName, each a SET OF
// AttributeTypeAndValue. `attrs` is [[oid, valueDerNode], ...], one RDN each.
function _name(attrs) {
  return asn1.readNode(asn1.writeSequence(attrs.map(function (pair) {
    return asn1.writeSet([asn1.writeSequence([asn1.writeOid(pair[0]), pair[1]])]);
  })));
}
function _multiValuedRdn(attrs) {
  return asn1.readNode(asn1.writeSequence([
    asn1.writeSet(attrs.map(function (pair) {
      return asn1.writeSequence([asn1.writeOid(pair[0]), pair[1]]);
    })),
  ]));
}

async function run() {
  var utf8 = _name([[OID_CN, asn1.writeUtf8String("Example CA")]]);
  var prnt = _name([[OID_CN, asn1.writePrintableString("Example CA")]]);
  check("the two fixtures really differ in DER",
    !Buffer.from(utf8.value).equals(Buffer.from(prnt.value)));
  check("PrintableString and UTF8String spell the same name",
    x509Chain.canonicalNameKey(utf8) === x509Chain.canonicalNameKey(prnt));

  var upper = _name([[OID_CN, asn1.writeUtf8String("EXAMPLE ca")]]);
  check("a case-insensitive attribute ignores case",
    x509Chain.canonicalNameKey(upper) === x509Chain.canonicalNameKey(utf8));

  var spaced = _name([[OID_CN, asn1.writeUtf8String("Example   CA")]]);
  check("repeated inner spaces collapse",
    x509Chain.canonicalNameKey(spaced) === x509Chain.canonicalNameKey(utf8));

  var padded = _name([[OID_CN, asn1.writeUtf8String("  Example CA  ")]]);
  check("leading and trailing spaces are ignored",
    x509Chain.canonicalNameKey(padded) === x509Chain.canonicalNameKey(utf8));

  // A different name must not collide, or the key would make the comparison
  // useless in the direction that matters.
  var other = _name([[OID_CN, asn1.writeUtf8String("Example CA 2")]]);
  check("a different common name keys differently",
    x509Chain.canonicalNameKey(other) !== x509Chain.canonicalNameKey(utf8));

  var twoRdns = _name([
    [OID_CN, asn1.writeUtf8String("Example CA")],
    [OID_O,  asn1.writeUtf8String("Example Org")],
  ]);
  check("an extra RDN keys differently from the name without it",
    x509Chain.canonicalNameKey(twoRdns) !== x509Chain.canonicalNameKey(utf8));

  // Attribute order inside ONE multi-valued RDN carries no meaning, so the two
  // orderings are one name; RDN order in the sequence does carry meaning.
  var mvA = _multiValuedRdn([
    [OID_CN, asn1.writeUtf8String("Example CA")],
    [OID_O,  asn1.writeUtf8String("Example Org")],
  ]);
  var mvB = _multiValuedRdn([
    [OID_O,  asn1.writeUtf8String("Example Org")],
    [OID_CN, asn1.writeUtf8String("Example CA")],
  ]);
  check("attribute order within one RDN does not change the key",
    x509Chain.canonicalNameKey(mvA) === x509Chain.canonicalNameKey(mvB));

  var reversed = _name([
    [OID_O,  asn1.writeUtf8String("Example Org")],
    [OID_CN, asn1.writeUtf8String("Example CA")],
  ]);
  check("RDN order in the sequence does change the key",
    x509Chain.canonicalNameKey(reversed) !== x509Chain.canonicalNameKey(twoRdns));

  // Malformed containers must not key at all. A key is a claim that the node
  // read as a Name, and a caller comparing keys treats equal keys as the same
  // name, so a structure that merely resembles one must refuse rather than
  // produce a key that collides with the valid encoding.
  var rdnAsSequence = asn1.readNode(asn1.writeSequence([
    asn1.writeSequence([asn1.writeSequence([    // SEQUENCE where a SET is required
      asn1.writeOid(OID_CN), asn1.writeUtf8String("Example CA"),
    ])]),
  ]));
  check("an RDN encoded as SEQUENCE rather than SET keys to null",
    x509Chain.canonicalNameKey(rdnAsSequence) === null,
    String(x509Chain.canonicalNameKey(rdnAsSequence)));
  check("and so cannot collide with the valid encoding of that name",
    x509Chain.canonicalNameKey(rdnAsSequence) !== x509Chain.canonicalNameKey(utf8));

  var emptyOctet = asn1.readNode(asn1.writeOctetString(Buffer.alloc(0)));
  check("an empty OCTET STRING keys to null rather than to an empty name",
    x509Chain.canonicalNameKey(emptyOctet) === null,
    String(x509Chain.canonicalNameKey(emptyOctet)));

  var emptyRdn = asn1.readNode(asn1.writeSequence([asn1.writeSet([])]));
  check("an RDN with no attributes keys to null",
    x509Chain.canonicalNameKey(emptyRdn) === null,
    String(x509Chain.canonicalNameKey(emptyRdn)));

  // An empty RDNSequence is a valid Name: RFC 5280 section 4.1.2.6 permits an
  // empty subject when the identity is carried in subjectAltName instead, so
  // refusing it would deny a caller the comparison this helper exists for.
  var emptyName = asn1.readNode(asn1.writeSequence([]));
  var emptyName2 = asn1.readNode(asn1.writeSequence([]));
  check("an empty RDNSequence is a name and keys to something usable",
    x509Chain.canonicalNameKey(emptyName) !== null,
    String(x509Chain.canonicalNameKey(emptyName)));
  check("two empty names are the same name",
    x509Chain.canonicalNameKey(emptyName) === x509Chain.canonicalNameKey(emptyName2));
  check("an empty name is not the same as a name with an attribute",
    x509Chain.canonicalNameKey(emptyName) !== x509Chain.canonicalNameKey(utf8));

  // Only the first value of an attribute reaches the key, so an attribute
  // carrying a second one would key identically to the well-formed attribute.
  var atvTwoValues = asn1.readNode(asn1.writeSequence([
    asn1.writeSet([asn1.writeSequence([
      asn1.writeOid(OID_CN),
      asn1.writeUtf8String("Example CA"),
      asn1.writeUtf8String("smuggled"),
    ])]),
  ]));
  check("an attribute carrying two values keys to null",
    x509Chain.canonicalNameKey(atvTwoValues) === null,
    String(x509Chain.canonicalNameKey(atvTwoValues)));
  check("so it cannot collide with the well-formed attribute",
    x509Chain.canonicalNameKey(atvTwoValues) !== x509Chain.canonicalNameKey(utf8));

  var atvMissingValue = asn1.readNode(asn1.writeSequence([
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_CN)])]),   // no value
  ]));
  check("an attribute with no value keys to null",
    x509Chain.canonicalNameKey(atvMissingValue) === null,
    String(x509Chain.canonicalNameKey(atvMissingValue)));

  var atvTypeNotOid = asn1.readNode(asn1.writeSequence([
    asn1.writeSet([asn1.writeSequence([
      asn1.writeUtf8String("2.5.4.3"), asn1.writeUtf8String("Example CA"),
    ])]),
  ]));
  check("an attribute whose type is not an OID keys to null",
    x509Chain.canonicalNameKey(atvTypeNotOid) === null,
    String(x509Chain.canonicalNameKey(atvTypeNotOid)));

  // A tag number alone does not identify a type. A context-specific or
  // constructed value carrying the same bytes is a different encoding, and
  // reading it as the universal string type would let a malformed issuer key
  // the same as the certificate it is being compared against.
  var ctxTagValue = _name([[OID_CN, asn1.writeNode(0x8c, Buffer.from("Example CA", "utf8"))]]);
  check("a context-specific value does not key as the universal UTF8String",
    x509Chain.canonicalNameKey(ctxTagValue) !== x509Chain.canonicalNameKey(utf8),
    String(x509Chain.canonicalNameKey(ctxTagValue)));

  var constructedValue = _name([[OID_CN, asn1.writeNode(0x2c, Buffer.from("Example CA", "utf8"))]]);
  check("a constructed value does not key as the primitive UTF8String",
    x509Chain.canonicalNameKey(constructedValue) !== x509Chain.canonicalNameKey(utf8),
    String(x509Chain.canonicalNameKey(constructedValue)));

  var constructedOid = asn1.readNode(asn1.writeSequence([
    asn1.writeSet([asn1.writeSequence([
      asn1.writeNode(0x26, asn1.writeOid(OID_CN).slice(2)),   // constructed OID
      asn1.writeUtf8String("Example CA"),
    ])]),
  ]));
  check("an attribute whose type is a constructed OID keys to null",
    x509Chain.canonicalNameKey(constructedOid) === null,
    String(x509Chain.canonicalNameKey(constructedOid)));
  check("so a constructed OID cannot alias the primitive one",
    x509Chain.canonicalNameKey(constructedOid) !== x509Chain.canonicalNameKey(utf8));

  // The opaque fallback must carry the tag too, or two unreadable values with
  // the same bytes under different tags would compare equal.
  var opaqueA = _name([[OID_CN, asn1.writeNode(0x0a, Buffer.from([1, 2, 3]))]]);
  var opaqueB = _name([[OID_CN, asn1.writeNode(0x0d, Buffer.from([1, 2, 3]))]]);
  check("two opaque values with one byte string but different tags key differently",
    x509Chain.canonicalNameKey(opaqueA) !== x509Chain.canonicalNameKey(opaqueB),
    String(x509Chain.canonicalNameKey(opaqueA)));

  // The null contract, and the trap it sets for a caller comparing keys.
  var notAName = asn1.readNode(asn1.writeInteger(Buffer.from([1])));
  check("a node that does not read as a Name keys to null",
    x509Chain.canonicalNameKey(notAName) === null);
  var alsoNot = asn1.readNode(asn1.writeOctetString(Buffer.from([2, 3])));
  check("two unreadable nodes both key to null, so equality alone would mislead",
    x509Chain.canonicalNameKey(notAName) === x509Chain.canonicalNameKey(alsoNot) &&
    x509Chain.canonicalNameKey(alsoNot) === null);

  console.log("OK — x509 canonical name key (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
