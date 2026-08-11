// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * RFC 9162 §2.1 Merkle tree — the recursive definitions, transcribed.
 *
 * This is deliberately NOT the framework's implementation. `lib/network-tls.js`
 * verifies inclusion and consistency with the iterative walk from §2.1.3 /
 * §2.1.4.2, which is the right shape for a verifier but shares no structure
 * with the tree definition it is supposed to implement. Transcribing the
 * recursive form here gives something to disagree with: build a real tree,
 * derive a real proof from it, and the verifier either agrees or it doesn't.
 *
 * Hand-built fixtures cannot do that job. A four-leaf tree with hand-derived
 * siblings is a perfect binary tree, so it never exercises the
 * largest-power-of-two split that the whole algorithm turns on — the case
 * where a tree is not a power of two is exactly where an off-by-one lives.
 *
 *   MTH({})      = SHA-256()
 *   MTH({d0})    = SHA-256(0x00 || d0)
 *   MTH(D[n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
 *                  k = largest power of 2 strictly less than n
 */

var nodeCrypto = require("node:crypto");

function _sha256(buf) { return nodeCrypto.createHash("sha256").update(buf).digest(); }

// The largest power of two strictly less than n (n > 1).
function largestPowerOf2LessThan(n) {
  var k = 1;
  while (k * 2 < n) k = k * 2;
  return k;
}

/** leafHash(d) — MTH({d}), the 0x00-prefixed leaf digest. */
function leafHash(d) { return _sha256(Buffer.concat([Buffer.from([0x00]), d])); }

/** innerHash(l, r) — the 0x01-prefixed interior digest. */
function innerHash(l, r) { return _sha256(Buffer.concat([Buffer.from([0x01]), l, r])); }

/** merkleTreeHash(entries) — MTH(D[n]) over an array of leaf-data Buffers. */
function merkleTreeHash(entries) {
  if (entries.length === 0) return _sha256(Buffer.alloc(0));
  if (entries.length === 1) return leafHash(entries[0]);
  var k = largestPowerOf2LessThan(entries.length);
  return innerHash(merkleTreeHash(entries.slice(0, k)), merkleTreeHash(entries.slice(k)));
}

/**
 * inclusionPath(m, entries) — PATH(m, D[n]) from §2.1.3: the audit path for
 * the m-th entry, bottom-up.
 *
 *   PATH(0, {d0}) = {}
 *   PATH(m, D[n]) = PATH(m, D[0:k])   : MTH(D[k:n])   when m < k
 *                 = PATH(m-k, D[k:n]) : MTH(D[0:k])   when m >= k
 */
function inclusionPath(m, entries) {
  if (entries.length === 1) return [];
  var k = largestPowerOf2LessThan(entries.length);
  if (m < k) {
    return inclusionPath(m, entries.slice(0, k)).concat([merkleTreeHash(entries.slice(k))]);
  }
  return inclusionPath(m - k, entries.slice(k)).concat([merkleTreeHash(entries.slice(0, k))]);
}

/**
 * consistencyProof(m, entries) — PROOF(m, D[n]) from §2.1.4: proof that the
 * tree of the first m entries is a prefix of the tree over all of them.
 *
 *   PROOF(m, D[n])          = SUBPROOF(m, D[n], true)
 *   SUBPROOF(m, D[m], true)  = {}
 *   SUBPROOF(m, D[m], false) = { MTH(D[m]) }
 *   SUBPROOF(m, D[n], b)     = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])   when m <= k
 *                            = SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k]) when m > k
 */
function consistencyProof(m, entries) {
  return _subproof(m, entries, true);
}

function _subproof(m, entries, b) {
  if (m === entries.length) return b ? [] : [merkleTreeHash(entries)];
  var k = largestPowerOf2LessThan(entries.length);
  if (m <= k) {
    return _subproof(m, entries.slice(0, k), b).concat([merkleTreeHash(entries.slice(k))]);
  }
  return _subproof(m - k, entries.slice(k), false).concat([merkleTreeHash(entries.slice(0, k))]);
}

/**
 * buildTree(n, labeller?) — a tree of n distinct entries plus everything a
 * proof test needs, so a case reads as a size rather than as a pile of hashes.
 *
 * @returns {object} { entries, size, root, pathFor(i), proofFrom(m), rootOfFirst(m) }
 *
 * @example
 *   var t = helpers.merkle.buildTree(7);
 *   var rv = b.network.tls.ct.verifyConsistency({
 *     firstSize: 3, firstRoot: t.rootOfFirst(3),
 *     secondSize: 7, secondRoot: t.root, proof: t.proofFrom(3),
 *   });
 *   // → rv.valid === true
 */
function buildTree(n, labeller) {
  var entries = [];
  for (var i = 0; i < n; i += 1) {
    // A labeller may return a Buffer, which is used as-is: real CT leaves are
    // MerkleTreeLeaf bytes with timestamps and length prefixes in them, and
    // round-tripping those through a utf8 string silently rewrites every byte
    // above 0x7f.
    var v = labeller ? labeller(i) : "entry-" + i;
    entries.push(Buffer.isBuffer(v) ? v : Buffer.from(v, "utf8"));
  }
  return {
    entries:  entries,
    size:     n,
    root:     merkleTreeHash(entries),
    pathFor:      function (i) { return inclusionPath(i, entries); },
    proofFrom:    function (m) { return consistencyProof(m, entries); },
    rootOfFirst:  function (m) { return merkleTreeHash(entries.slice(0, m)); },
    leafHashAt:   function (i) { return leafHash(entries[i]); },
  };
}

module.exports = {
  leafHash:                 leafHash,
  innerHash:                innerHash,
  merkleTreeHash:           merkleTreeHash,
  inclusionPath:            inclusionPath,
  consistencyProof:         consistencyProof,
  largestPowerOf2LessThan:  largestPowerOf2LessThan,
  buildTree:                buildTree,
};
