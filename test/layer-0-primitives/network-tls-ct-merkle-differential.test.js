// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.tls.ct.verifyConsistency — checked against real trees.
 *
 * The framework verifies a consistency proof with the iterative walk from
 * RFC 9162 §2.1.4.2. That walk is correct for the same reason the recursive
 * definition in §2.1.4 is, but it shares no structure with it, so it cannot be
 * checked by reading — only by disagreement. helpers.merkle transcribes the
 * recursive definitions, builds a real tree, and derives a real proof; this
 * suite feeds those proofs to the verifier for every (first size, second size)
 * pair up to a bound, and then breaks them one way at a time.
 *
 * Every pair matters because the algorithm turns on the largest power of two
 * strictly less than the tree size. A four-leaf fixture — the shape a
 * hand-built test reaches for — is a perfect binary tree, so it never splits
 * unevenly and never exercises the case an off-by-one would live in.
 *
 * Run standalone: node test/layer-0-primitives/network-tls-ct-merkle-differential.test.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var merkle  = helpers.merkle;

var MAX_TREE = 17;                                                                               // allow:raw-byte-literal — past 16 so a non-power-of-two split is covered above and below

// Every m <= n up to MAX_TREE, proof derived from the real tree. A single
// failing pair names its own sizes, so a break reads as "3 into 7" rather than
// as one opaque assertion over the whole sweep.
function testEveryConsistencyPairVerifies() {
  var failures = [];
  var pairs = 0;
  for (var n = 1; n <= MAX_TREE; n += 1) {
    var tree = merkle.buildTree(n);
    for (var m = 1; m <= n; m += 1) {
      pairs += 1;
      var rv = b.network.tls.ct.verifyConsistency({
        firstSize:  m,
        firstRoot:  tree.rootOfFirst(m),
        secondSize: n,
        secondRoot: tree.root,
        proof:      tree.proofFrom(m),
      });
      if (rv.valid !== true) failures.push(m + "->" + n + " (" + (rv.reason || "?") + ")");
    }
  }
  check("every consistency pair up to " + MAX_TREE + " leaves verifies (" + pairs + " pairs)",
        failures.length === 0);
  if (failures.length) {
    check("failing pairs: " + failures.slice(0, 8).join(", "), false);
  }
}

// A proof that verifies for the tree it came from must not verify against a
// different tree of the same shape — otherwise the walk is checking arithmetic
// rather than hashes.
function testAProofDoesNotTransferToAnotherTree() {
  var a = merkle.buildTree(9);
  var other = merkle.buildTree(9, function (i) { return "different-" + i; });
  var rv = b.network.tls.ct.verifyConsistency({
    firstSize:  4,
    firstRoot:  a.rootOfFirst(4),
    secondSize: 9,
    secondRoot: other.root,                      // the wrong tree's root
    proof:      a.proofFrom(4),
  });
  check("a valid proof against another tree's root is refused", rv.valid === false);
  check("the refusal is a root mismatch, not a shape complaint",
        rv.reason === "root-mismatch");
}

// The point of pinning an STH is the claim "the tree I pinned is a prefix of
// the tree you are showing me now". A proof that rebuilds some OTHER first
// tree of the same size satisfies the second half and not the first, so it
// must be refused — otherwise the pin is decorative.
function testTheProofMustConnectToThePinnedFirstRoot() {
  var real  = merkle.buildTree(11);
  var other = merkle.buildTree(11, function (i) { return "other-" + i; });

  [3, 5, 6, 7, 9].forEach(function (m) {                                                         // sizes that are not powers of two
    var rv = b.network.tls.ct.verifyConsistency({
      firstSize:  m,
      firstRoot:  other.rootOfFirst(m),           // a first tree the proof does not describe
      secondSize: real.size,
      secondRoot: real.root,
      proof:      real.proofFrom(m),
    });
    check("a proof for a different first tree of size " + m + " is refused",
          rv.valid === false && rv.reason === "first-root-mismatch");
  });

  // The pinned root that IS this tree's prefix still verifies at each size.
  [3, 5, 6, 7, 9].forEach(function (m) {
    var rv = b.network.tls.ct.verifyConsistency({
      firstSize: m, firstRoot: real.rootOfFirst(m),
      secondSize: real.size, secondRoot: real.root, proof: real.proofFrom(m),
    });
    check("the genuine pinned root at size " + m + " still verifies", rv.valid === true);
  });
}

// A tree is consistent with itself, and RFC 9162 §2.1.4 says so with an empty
// proof. Sizes that are not powers of two are the ones that matter here: the
// index bits of a power-of-two size shift to zero on their own.
function testATreeIsConsistentWithItself() {
  [1, 2, 3, 4, 5, 7, 8, 11, 16, 17].forEach(function (n) {
    var t = merkle.buildTree(n);
    var rv = b.network.tls.ct.verifyConsistency({
      firstSize: n, firstRoot: t.root, secondSize: n, secondRoot: t.root, proof: [],
    });
    check("a " + n + "-leaf tree is consistent with itself on an empty proof",
          rv.valid === true);
  });

  var t8 = merkle.buildTree(8);
  var nonEmpty = b.network.tls.ct.verifyConsistency({
    firstSize: 8, firstRoot: t8.root, secondSize: 8, secondRoot: t8.root,
    proof: [Buffer.alloc(32, 0x00)],
  });
  check("equal sizes with a non-empty proof are refused", nonEmpty.valid === false);

  var t5 = merkle.buildTree(5);
  var wrongRoot = b.network.tls.ct.verifyConsistency({
    firstSize: 5, firstRoot: t5.root, secondSize: 5,
    secondRoot: Buffer.alloc(32, 0xcc), proof: [],
  });
  check("equal sizes with disagreeing roots are still refused", wrongRoot.valid === false);
}

// Math.floor(Infinity) === Infinity, so an integer check alone lets an
// infinite tree size through. There is no such tree, and the equal-sizes
// shortcut has no loop to run out of, so the refusal has to be explicit.
function testNonFiniteTreeSizesAreRefused() {
  var t = merkle.buildTree(4);
  [
    { firstSize: Infinity, secondSize: Infinity, what: "both sizes infinite" },
    { firstSize: 4, secondSize: Infinity, what: "an infinite second size" },
    { firstSize: Infinity, secondSize: 4, what: "an infinite first size" },
    { firstSize: NaN, secondSize: 4, what: "a NaN first size" },
    { firstSize: 4, secondSize: NaN, what: "a NaN second size" },
  ].forEach(function (c) {
    var rv = b.network.tls.ct.verifyConsistency({
      firstSize: c.firstSize, secondSize: c.secondSize,
      firstRoot: t.root, secondRoot: t.root, proof: [],
    });
    check("verifyConsistency refuses " + c.what, rv.valid === false);
  });
}

// The same distinction has to survive composition: verifyInclusion runs the
// consistency check inside itself, and a mismatched pinned root there means
// the same thing it means standalone.
function testTheComposedInclusionPathKeepsTheFirstRootReason() {
  // The inclusion half has to actually PASS, or the call never reaches the
  // consistency block and the assertion below would hold for the wrong reason.
  // signedEntryDer supplies the logged entry directly, so no certificate
  // parsing stands between here and the walk.
  var ts = 1700000000000;                                                                        // allow:raw-time-literal — a fixed SCT timestamp, not a duration

  // RFC 9162 §4.6 MerkleTreeLeaf bytes for the i-th logged entry, so the tree
  // below is a tree of real leaves and its audit path is the real one. Both
  // halves of the call then run against ONE tree, which is what makes the
  // consistency block reachable at all.
  function leafBytesFor(i) {
    var signedEntry = Buffer.from("CERT-DER-BYTES-" + i);
    var tsBuf = Buffer.alloc(8);
    tsBuf.writeBigUInt64BE(BigInt(ts));
    var lenBuf = Buffer.alloc(3);
    lenBuf.writeUIntBE(signedEntry.length, 0, 3);
    return {
      signedEntry: signedEntry,
      bytes: Buffer.concat([
        Buffer.from([0x00]), Buffer.from([0x00]), tsBuf, Buffer.from([0x00, 0x00]),
        lenBuf, signedEntry, Buffer.from([0x00, 0x00]),
      ]),
    };
  }
  var leaves = [];
  for (var i = 0; i < 11; i += 1) leaves.push(leafBytesFor(i));
  var tree = merkle.buildTree(11, function (idx) { return leaves[idx].bytes; });

  var inclusion = {
    sct:             { logIdHex: "abc", timestamp: ts, signedEntryDer: leaves[0].signedEntry },
    leafCertificate: Buffer.from("placeholder"),
    leafIndex:       0,
    auditPath:       tree.pathFor(0),
    sthFromLog:      { treeSize: 11, rootHash: tree.root },
  };
  check("the inclusion half of the composed call verifies on its own",
        b.network.tls.ct.verifyInclusion(inclusion).valid === true);

  var other = merkle.buildTree(11, function (idx) { return "other-" + idx; });
  var rv = b.network.tls.ct.verifyInclusion(Object.assign({}, inclusion, {
    consistency: { firstSize: 5, firstRoot: other.rootOfFirst(5), proof: tree.proofFrom(5) },
  }));
  check("a wrong pinned root inside verifyInclusion is refused", rv.valid === false);
  check("and it keeps the pinned-history reason rather than reading as a malformed proof",
        rv.reason === "first-root-mismatch");
}

// Each of these breaks exactly one thing in an otherwise-valid proof.
function testBrokenConsistencyProofsAreRefused() {
  var t = merkle.buildTree(11);
  var m = 5;
  function withProof(mut) {
    var proof = t.proofFrom(m).map(function (h) { return Buffer.from(h); });
    var args = {
      firstSize: m, firstRoot: t.rootOfFirst(m),
      secondSize: t.size, secondRoot: t.root, proof: proof,
    };
    mut(args);
    var threw = null, rv = null;
    try { rv = b.network.tls.ct.verifyConsistency(args); } catch (e) { threw = e; }
    return { rv: rv, threw: threw };
  }

  var flipped = withProof(function (a) { a.proof[0][0] ^= 0x01; });
  check("a proof with one flipped bit is refused",
        flipped.threw !== null || (flipped.rv && flipped.rv.valid === false));

  var truncated = withProof(function (a) { a.proof.pop(); });
  check("a truncated proof is refused",
        truncated.threw !== null || (truncated.rv && truncated.rv.valid === false));

  var padded = withProof(function (a) { a.proof.push(Buffer.alloc(32, 0x00)); });
  check("a proof with a trailing extra sibling is refused",
        padded.threw !== null || (padded.rv && padded.rv.valid === false));

  var shortHash = withProof(function (a) { a.proof[a.proof.length - 1] = Buffer.alloc(16, 0x01); });
  check("a proof entry that is not a 32-byte hash is refused",
        shortHash.threw !== null || (shortHash.rv && shortHash.rv.valid === false));

  var wrongFirstRoot = withProof(function (a) { a.firstRoot = Buffer.alloc(32, 0xcc); });
  check("a first root that is not this tree's prefix root is refused",
        wrongFirstRoot.threw !== null || (wrongFirstRoot.rv && wrongFirstRoot.rv.valid === false));
}

// Shape refusals — the arguments themselves are wrong, before any hashing.
function testConsistencyArgumentRefusals() {
  var t = merkle.buildTree(8);
  function call(over) {
    var args = Object.assign({
      firstSize: 4, firstRoot: t.rootOfFirst(4),
      secondSize: 8, secondRoot: t.root, proof: t.proofFrom(4),
    }, over);
    var threw = null, rv = null;
    try { rv = b.network.tls.ct.verifyConsistency(args); } catch (e) { threw = e; }
    return { rv: rv, threw: threw, code: threw && threw.code };
  }

  var backwards = call({ firstSize: 8, secondSize: 4 });
  check("a second tree smaller than the first is refused",
        backwards.threw !== null || (backwards.rv && backwards.rv.valid === false));

  var zeroFirst = call({ firstSize: 0 });
  check("a first size of zero is refused",
        zeroFirst.threw !== null || (zeroFirst.rv && zeroFirst.rv.valid === false));

  var fractional = call({ firstSize: 2.5 });
  check("a fractional tree size is refused",
        fractional.threw !== null || (fractional.rv && fractional.rv.valid === false));

  var badFirstHash = call({ firstRoot: Buffer.alloc(8, 0x00) });
  check("a first root that is not 32 bytes is refused",
        badFirstHash.threw !== null || (badFirstHash.rv && badFirstHash.rv.valid === false));

  var notAnArray = call({ proof: "not-an-array" });
  check("a proof that is not an array is refused",
        notAnArray.threw !== null || (notAnArray.rv && notAnArray.rv.valid === false));
}

// The two implementations must agree on the tree hash itself, not just on the
// proofs derived from it — a shared mistake in both would cancel out.
function testTreeHashesAgreeWithTheDefinition() {
  var one = merkle.buildTree(1);
  check("a single-entry tree root is the leaf hash",
        one.root.equals(merkle.leafHash(one.entries[0])));

  var two = merkle.buildTree(2);
  check("a two-entry tree root is the interior hash of its leaves",
        two.root.equals(merkle.innerHash(merkle.leafHash(two.entries[0]),
                                         merkle.leafHash(two.entries[1]))));

  // The uneven split is the whole point: for n=3 the left subtree is the first
  // TWO entries, not the first one.
  var three = merkle.buildTree(3);
  var expected = merkle.innerHash(
    merkle.innerHash(merkle.leafHash(three.entries[0]), merkle.leafHash(three.entries[1])),
    merkle.leafHash(three.entries[2]));
  check("a three-entry tree splits 2/1, not 1/2", three.root.equals(expected));

  check("the power-of-two split is strictly less than the size",
        merkle.largestPowerOf2LessThan(3) === 2 &&
        merkle.largestPowerOf2LessThan(4) === 2 &&
        merkle.largestPowerOf2LessThan(5) === 4 &&
        merkle.largestPowerOf2LessThan(17) === 16);
}

async function run() {
  testTreeHashesAgreeWithTheDefinition();
  testEveryConsistencyPairVerifies();
  testAProofDoesNotTransferToAnotherTree();
  testTheProofMustConnectToThePinnedFirstRoot();
  testATreeIsConsistentWithItself();
  testNonFiniteTreeSizesAreRefused();
  testTheComposedInclusionPathKeepsTheFirstRootReason();
  testBrokenConsistencyProofsAreRefused();
  testConsistencyArgumentRefusals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.message) || e); process.exit(1); }
  );
}
