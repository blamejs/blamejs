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

  // RFC 4518 section 2.2 maps tab, the line and page separators, NEL and every
  // space-separator character to U+0020 before insignificant spaces collapse, so
  // a name written with any of them is the same name. Leaving them unmapped
  // refuses an otherwise valid SignerInfo whose issuer uses one.
  ["\t", "\n", "\u000b", "\f", "\r", "\u0085", " ", " ", " ",
   " ", " ", "　"].forEach(function (ws) {
    var withWs = _name([[OID_CN, asn1.writeUtf8String("Example" + ws + "CA")]]);
    check("U+" + ws.codePointAt(0).toString(16).padStart(4, "0") +
          " is mapped to a space before comparison",
      x509Chain.canonicalNameKey(withWs) === x509Chain.canonicalNameKey(utf8));
  });

  // RFC 4518 section 2.2 also maps a set of characters to NOTHING: the soft
  // hyphen, the combining grapheme joiner, the variation selectors, the zero
  // width space, the object replacement character, and every remaining control
  // and format code point. A name carrying one of them is the same name, and
  // leaving them in refuses a valid SignerInfo whose issuer spells it that way.
  ["­", "​", "͏", "᠋", "︀", "️", "￼",
   "‍", "\u0001"].forEach(function (nil) {
    var withNil = _name([[OID_CN, asn1.writeUtf8String("Exam" + nil + "ple CA")]]);
    check("U+" + nil.codePointAt(0).toString(16).padStart(4, "0") +
          " is removed before comparison",
      x509Chain.canonicalNameKey(withNil) === x509Chain.canonicalNameKey(utf8),
      String(x509Chain.canonicalNameKey(withNil)));
  });

  // The set of removed characters is a FIXED table, not a category test against
  // whatever Unicode version the runtime ships. A deletion is the one mapping that
  // can make two DIFFERENT names equal, so a character the RFC never listed must
  // not be deleted just because a later Unicode assigned it a format category.
  // RFC 4518 section 2.4 prohibits the code points unassigned in Unicode 3.2, and
  // refusing is the only safe answer: deleting collapses two names, and no
  // conformant peer sends one.
  [["؜", "ARABIC LETTER MARK, Cf since Unicode 6.3"],
   ["⁥", "unassigned"],
   ["​؜", "a deleted character beside a prohibited one"],
   ["󰀀", "a private-use code point"]].forEach(function (pair) {
    var bad = _name([[OID_CN, asn1.writeUtf8String("A" + pair[0] + "B")]]);
    var key = x509Chain.canonicalNameKey(bad);
    check("a prohibited code point refuses the name rather than keying it (" +
          pair[1] + ")", key === null, String(key));
  });

  // The failure that motivates it, stated as the comparison it would have broken.
  var plainAb = _name([[OID_CN, asn1.writeUtf8String("AB")]]);
  var withAlm = _name([[OID_CN, asn1.writeUtf8String("A؜B")]]);
  check("so an issuer carrying one does NOT take the key of the name without it",
    x509Chain.canonicalNameKey(withAlm) !== x509Chain.canonicalNameKey(plainAb),
    String(x509Chain.canonicalNameKey(withAlm)) + " vs " +
    String(x509Chain.canonicalNameKey(plainAb)));
  check("and the name without it still keys",
    x509Chain.canonicalNameKey(plainAb) !== null);

  // Case-insensitive matching is RFC 4518 case FOLDING, which is not simple
  // lowercasing: the sharp s folds to two letters, so a CN written one way and
  // its all-caps spelling are one name. Lowercasing alone leaves them different
  // and refuses the envelope.
  var sharp = _name([[OID_CN, asn1.writeUtf8String("Straße CA")]]);
  var caps  = _name([[OID_CN, asn1.writeUtf8String("STRASSE CA")]]);
  check("the sharp s folds to ss, so the all-caps spelling is the same name",
    x509Chain.canonicalNameKey(sharp) === x509Chain.canonicalNameKey(caps),
    x509Chain.canonicalNameKey(sharp) + " vs " + x509Chain.canonicalNameKey(caps));
  var capSharp = _name([[OID_CN, asn1.writeUtf8String("ẞTRASSE CA")]]);
  var sharpLow = _name([[OID_CN, asn1.writeUtf8String("ßtrasse CA")]]);
  check("the capital sharp s folds the same way its lowercase form does",
    x509Chain.canonicalNameKey(capSharp) === x509Chain.canonicalNameKey(sharpLow),
    x509Chain.canonicalNameKey(capSharp) + " vs " + x509Chain.canonicalNameKey(sharpLow));

  // Final sigma and medial sigma fold together; lowercasing keeps them apart.
  var finalSigma = _name([[OID_CN, asn1.writeUtf8String("ςigma CA")]]);
  var capSigma   = _name([[OID_CN, asn1.writeUtf8String("ΣIGMA CA")]]);
  check("final sigma folds onto the medial form",
    x509Chain.canonicalNameKey(finalSigma) === x509Chain.canonicalNameKey(capSigma),
    x509Chain.canonicalNameKey(finalSigma) + " vs " + x509Chain.canonicalNameKey(capSigma));

  // Case mapping can hand back a DECOMPOSED sequence, so the normalization has
  // to follow the fold rather than precede it. Normalizing first leaves the
  // precomposed j-with-caron and the j plus combining caron different.
  var precomposed = _name([[OID_CN, asn1.writeUtf8String("ǰ CA")]]);
  var decomposed  = _name([[OID_CN, asn1.writeUtf8String("J̌ CA")]]);
  check("a precomposed letter and its decomposed spelling are one name",
    x509Chain.canonicalNameKey(precomposed) === x509Chain.canonicalNameKey(decomposed),
    x509Chain.canonicalNameKey(precomposed) + " vs " + x509Chain.canonicalNameKey(decomposed));

  // The Greek iota-subscript forms expand under folding, and the expansion is
  // what the all-caps spelling lowercases to.
  // U+1F88 already carries the subscript, so the all-caps spelling of U+1F80 is
  // U+1F08 followed by a separate capital iota.
  var iotaSub = _name([[OID_CN, asn1.writeUtf8String("ᾀ CA")]]);
  var iotaCap = _name([[OID_CN, asn1.writeUtf8String("ἈΙ CA")]]);
  check("an iota-subscript form folds onto its expanded spelling",
    x509Chain.canonicalNameKey(iotaSub) === x509Chain.canonicalNameKey(iotaCap),
    x509Chain.canonicalNameKey(iotaSub) + " vs " + x509Chain.canonicalNameKey(iotaCap));

  // Normalization is to form C, not form KC, and the difference is the whole
  // safety of the comparison. Compatibility normalization maps one character onto
  // a DIFFERENT one, so under form KC 24,355 pairs of unrelated code points took
  // the same key: every superscript, subscript, circled, fullwidth and
  // mathematical variant collapsed onto its ASCII base. U+1D2C is category Lm, so
  // no category test excludes it, and NFKC maps it to `A`. Canonical
  // normalization only composes and reorders, so it never maps a character onto
  // another one, and these must stay distinct.
  [["ᴬ", "modifier letter capital A, which NFKC maps to A"],
   ["\u{1d400}", "mathematical bold capital A"],
   ["Ａ", "fullwidth capital A"],
   ["①", "circled digit one"]].forEach(function (pair) {
    var variant = _name([[OID_CN, asn1.writeUtf8String("A" + pair[0] + "B CA")]]);
    var plain   = _name([[OID_CN, asn1.writeUtf8String("A" + pair[0].normalize("NFKC") + "B CA")]]);
    check("a compatibility variant does NOT take the key of what NFKC maps it to (" +
          pair[1] + ")",
      x509Chain.canonicalNameKey(variant) !== x509Chain.canonicalNameKey(plain),
      String(x509Chain.canonicalNameKey(variant)));
  });

  // The legacy string types carry a restricted repertoire, and decoding bytes
  // outside it as Latin-1 fed preparation characters that were never in the
  // input: a PrintableString holding the bytes 41 00 42 decoded to A, NUL, B, and
  // the NUL was then deleted, so it took the key of the valid PrintableString
  // `AB`. A value outside its type's repertoire now keys by its BYTES, which can
  // only equal an identical byte sequence.
  var validAb = _name([[OID_CN, asn1.writePrintableString("AB")]]);
  [[Buffer.from([0x41, 0x00, 0x42]), "a NUL byte"],
   [Buffer.from([0x41, 0xad, 0x42]), "a byte that would decode to SOFT HYPHEN"],
   [Buffer.from([0x41, 0x2a, 0x42]), "an asterisk, outside the PrintableString set"]
  ].forEach(function (pair) {
    var tlv = Buffer.concat([Buffer.from([0x13, pair[0].length]), pair[0]]);
    var raw = _name([[OID_CN, tlv]]);
    var key = x509Chain.canonicalNameKey(raw);
    check("a PrintableString holding " + pair[1] +
          " does not take the key of the valid string",
      key !== x509Chain.canonicalNameKey(validAb), String(key));
    check("and it keys by its bytes rather than as text (" + pair[1] + ")",
      key !== null && key.indexOf("b:") !== -1, String(key));
  });

  // And the key is a fixed point: feeding the prepared text back in changes
  // nothing. A preparation that still moved would mean two callers comparing at
  // different depths could disagree about one name.
  var settled = _name([[OID_CN, asn1.writeUtf8String("strasse ca")]]);
  check("an already-prepared value keys to itself",
    x509Chain.canonicalNameKey(settled) === x509Chain.canonicalNameKey(sharp),
    x509Chain.canonicalNameKey(settled) + " vs " + x509Chain.canonicalNameKey(sharp));

  // Normalization runs BEFORE each fold, not only after it. U+0345 folds into a
  // base letter, so folding an unordered mark run first moves the accent onto a
  // different letter and no later pass can put it back. Checked as a class: every
  // ordering of a mark run that NFC reads as one string must key alike, over mark
  // sets that include the one which folds.
  // The combining grapheme joiner is itself removed, and removing it can leave a
  // mark run that still needs ordering, so the mapping and the normalization have
  // to settle TOGETHER before the fold runs. Every placement of the joiner inside
  // a mark run is covered, not just the one a review happened to name.
  var MARKS = ["ͅ", "́", "̈", "̌"];
  var CGJ = "͏";
  var compared = 0;
  var disagreed = [];
  function _keyOf(text) {
    return x509Chain.canonicalNameKey(
      _name([[OID_CN, asn1.writeUtf8String(text + " CA")]]));
  }
  ["α", "a", "η"].forEach(function (base) {
    MARKS.forEach(function (m1) {
      MARKS.forEach(function (m2) {
        if (m1 === m2) return;
        [m1 + m2, m2 + m1].forEach(function (run) {
          var variants = [run];
          for (var at = 0; at <= run.length; at += 1) {
            variants.push(run.slice(0, at) + CGJ + run.slice(at));
          }
          var reference = base + m1 + m2;
          variants.forEach(function (v) {
            // Compare only the variants that really are the same name once the
            // joiner is gone and the marks are ordered.
            if ((base + v).split(CGJ).join("").normalize("NFC") !==
                reference.normalize("NFC")) return;
            compared += 1;
            if (_keyOf(base + v) !== _keyOf(reference)) {
              disagreed.push(JSON.stringify(base + v) + " vs " + JSON.stringify(reference));
            }
          });
        });
      });
    });
  });
  check("the mark fixtures produced equivalent variants to compare", compared >= 20,
    compared + " variants");
  check("every equivalent mark ordering and joiner placement keys alike",
    disagreed.length === 0, disagreed.slice(0, 4).join("; "));

  // The control: the fold must not reach FURTHER than the default rules. The
  // dotless i folds to an ASCII i only under the Turkic rules, which RFC 4518
  // does not use, so these two are different names and a key that merged them
  // would let one issuer be read as another.
  var dotless = _name([[OID_CN, asn1.writeUtf8String("ıstanbul CA")]]);
  var dotted  = _name([[OID_CN, asn1.writeUtf8String("Istanbul CA")]]);
  check("the dotless i is NOT folded onto an ASCII i",
    x509Chain.canonicalNameKey(dotless) !== x509Chain.canonicalNameKey(dotted),
    x509Chain.canonicalNameKey(dotless) + " vs " + x509Chain.canonicalNameKey(dotted));

  var mixedRun = _name([[OID_CN, asn1.writeUtf8String("Example \t 　 CA")]]);
  check("a run of mixed separators collapses to one space",
    x509Chain.canonicalNameKey(mixedRun) === x509Chain.canonicalNameKey(utf8));

  var wsPadded = _name([[OID_CN, asn1.writeUtf8String("\tExample CA\r\n")]]);
  check("leading and trailing separators are ignored too",
    x509Chain.canonicalNameKey(wsPadded) === x509Chain.canonicalNameKey(utf8));

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

  // The completeness proof for the whole comparison, over every code point rather
  // than the cases anyone thought of. Two DIFFERENT names must not take one key.
  // Two case variants taking one key is not that: the attribute is
  // caseIgnoreMatch, so unifying them is the specified behaviour, and a Georgian
  // Mtavruli capital folding onto its Mkhedruli letter is the same event as `A`
  // folding onto `a`.
  //
  // So: group every code point by its key and require each group to be a single
  // Unicode case class. Run against a build that normalizes to form KC instead of
  // form C, the same scan reports 24,355 pairs that share a key without being case
  // variants, because a compatibility variant is NOT a case variant of what it maps
  // to. It is the assertion that would catch that reintroduction, or any other rule
  // that merged two letters.
  function caseClass(ch) {
    var seen = {};
    var frontier = [ch];
    while (frontier.length) {
      var next = [];
      frontier.forEach(function (c) {
        [c.toLowerCase(), c.toUpperCase(), c.toUpperCase().toLowerCase(),
         c.normalize("NFD").toLowerCase()].forEach(function (v) {
          if (!seen[v]) { seen[v] = true; next.push(v); }
        });
      });
      frontier = next;
    }
    return seen;
  }
  function caseRelated(a, b) {
    var ca = caseClass(a);
    return Object.keys(caseClass(b)).some(function (v) { return ca[v]; });
  }

  var byKey = {};
  var scanned = 0;
  var keyed = 0;
  var emptyKey = x509Chain.canonicalNameKey(_name([[OID_CN, asn1.writeUtf8String(" ")]]));
  for (var cp = 0x21; cp <= 0x2ffff; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    scanned += 1;
    var ch = String.fromCodePoint(cp);
    var k = x509Chain.canonicalNameKey(_name([[OID_CN, asn1.writeUtf8String(ch)]]));
    if (k === null || k === emptyKey) continue;
    keyed += 1;
    if (!byKey[k]) byKey[k] = [];
    byKey[k].push(ch);
  }
  // The premise: a prohibition that grew to refuse most of Unicode would make the
  // assertion below vacuous, so the share that actually reaches a key is checked.
  check("most of the scanned code points reach a key, so the comparison below is " +
        "not running over a handful",
        keyed * 2 > scanned, keyed + " of " + scanned + " code points keyed");
  var shared = Object.keys(byKey).filter(function (k) { return byKey[k].length > 1; });
  var notCase = [];
  shared.forEach(function (k) {
    var g = byKey[k];
    for (var i = 0; i < g.length; i += 1) {
      for (var j = i + 1; j < g.length; j += 1) {
        if (!caseRelated(g[i], g[j])) {
          notCase.push("U+" + g[i].codePointAt(0).toString(16).toUpperCase() +
            " vs U+" + g[j].codePointAt(0).toString(16).toUpperCase());
        }
      }
    }
  });
  // A name the preparation refuses still has to equal ITSELF. Treating a refused
  // name as unequal to every name, including a byte-identical one, refused
  // conforming input: a SignerInfo whose sid issuer field is copied verbatim from
  // its certificate stopped binding, so a valid envelope raised
  // mail-crypto/smime/signer-cert-not-named, and a self-issued rollover whose
  // subject bytes equal its issuer bytes stopped counting as self-issued, so
  // pathLenSatisfied rejected a chain RFC 5280 6.1.4(l) exempts. Byte equality is
  // the strictest comparison there is and cannot merge two different names, so it
  // is what answers when canonicalization will not.
  var gaiji = String.fromCodePoint(0xf8ff);
  var refusedA = _name([[OID_CN, asn1.writeUtf8String("Acme " + gaiji + " Root CA")]]);
  var refusedCopy = _name([[OID_CN, asn1.writeUtf8String("Acme " + gaiji + " Root CA")]]);
  var refusedB = _name([[OID_CN, asn1.writeUtf8String("Other " + gaiji + " Root CA")]]);
  check("a name the preparation refuses has no key",
        x509Chain.canonicalNameKey(refusedA) === null);
  check("two byte-identical names match even when neither can be canonicalized",
        x509Chain.sameName(refusedA, refusedCopy) === true);
  check("two DIFFERENT uncanonicalizable names still do not match",
        x509Chain.sameName(refusedA, refusedB) === false);
  check("an uncanonicalizable name does not match a readable one",
        x509Chain.sameName(refusedA, utf8) === false);
  check("two readable spellings of one name still match through sameName",
        x509Chain.sameName(utf8, prnt) === true);

  check("the scan compared enough code points to be meaningful",
        shared.length > 1000, shared.length + " keys are shared by more than one code point");
  check("every code point sharing a key with another is its CASE variant, so no two " +
        "different letters take one key",
        notCase.length === 0, notCase.slice(0, 6).join("; "));

  console.log("OK — x509 canonical name key (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
