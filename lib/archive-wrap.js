"use strict";
/**
 * archive-wrap — recipient-based whole-archive encryption substrate
 * for the b.archive family. Composes b.crypto.encrypt (ML-KEM-1024 +
 * P-384 ECDH hybrid + SHAKE256 + XChaCha20-Poly1305 envelope) so
 * archive bytes hitting an adapter can be a sealed envelope rather
 * than the raw format.
 *
 * Operators compose explicitly for v0.12.10:
 *
 *   var sealed = b.archive.wrap(t.toBuffer(), { recipient: pubKeys });
 *   await b.archive.adapters.fs(path).write(sealed);
 *
 *   var sealed = await fs.promises.readFile(path);
 *   var bytes  = b.archive.unwrap(sealed, { recipient: privKeys });
 *   var reader = b.archive.read.tar(b.archive.adapters.buffer(bytes));
 *
 * Builder-fluent composition (`tarBuilder.toAdapter(s3, { wrap: ... })`)
 * + per-entry ZIP wrap (Flavor 2) land in v0.12.11 alongside the
 * backup-crypto refactor; this patch ships the recipient substrate
 * + the b.backup `cryptoStrategy: "recipient"` opt that consumes it.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var ArchiveWrapError = defineClass("ArchiveWrapError", { alwaysPermanent: true });

var bCrypto = lazyRequire(function () { return require("./crypto"); });

// Envelope magic — 5-byte ASCII prefix the safe-archive sniffer
// recognises. Distinct from b.crypto.encrypt's base64 envelope so
// archive-wrap output can carry an unambiguous "this is an archive
// recipient-wrap envelope" magic before the operator-controlled
// payload.
var ARCH_WRAP_MAGIC = "BAWRP";                                                       // allow:raw-byte-literal — 5-byte ASCII archive-wrap envelope magic
var ARCH_WRAP_VERSION = 0x01;                                                        // allow:raw-byte-literal — version byte
var ARCH_WRAP_HEADER_BYTES = C.BYTES.bytes(6);                                        // magic(5) + version(1)

/**
 * @primitive b.archive.wrap
 * @signature b.archive.wrap(bytes, opts)
 * @since     0.12.10
 * @status    stable
 * @related   b.archive.unwrap, b.crypto.encrypt, b.backup.bundleAdapterStorage
 *
 * Wrap archive bytes in a recipient-encrypted envelope. The envelope
 * is the framework's standard hybrid PQC seal (ML-KEM-1024 + P-384
 * ECDH hybrid + SHAKE256 KDF + XChaCha20-Poly1305 AEAD) prefixed
 * with a 6-byte archive-wrap header (`BAWRP` magic + version byte)
 * so format sniffers can distinguish wrap envelopes from raw
 * archives without trial decryption.
 *
 * Recipient strategies:
 *   - static key  — `{ recipient: { publicKey, ecPublicKey } }` (ML-KEM-1024
 *                   pubkey PEM + P-384 ECDH pubkey PEM).
 *   - peer cert   — `{ recipient: { peerCertDer, peerKemPubkey } }` composes
 *                   `b.crypto.encryptEnvelopeAsCertPeer` (extracts the
 *                   P-384 half from the cert).
 *   - tenant      — `{ recipient: "tenant", tenantId: "alpha" }` resolves
 *                   the tenant's KEM keypair via `b.vault.derivedKey`
 *                   (deferred to v0.12.11 alongside the backup
 *                   `cryptoStrategy: "recipient"` adoption).
 *
 * @opts
 *   recipient:  object | string,   // see strategies above; required
 *   tenantId:   string,            // required when recipient === "tenant"
 *
 * @example
 *   var pair   = b.crypto.generateEncryptionKeyPair();
 *   var sealed = b.archive.wrap(tarBytes, { recipient: pair });
 *   // sealed is a Buffer carrying BAWRP+version+envelope; write to
 *   // any adapter sink. On read, hand to b.archive.unwrap with the
 *   // matching privKeys to recover tarBytes.
 */
function wrap(bytes, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new ArchiveWrapError("archive-wrap/bad-input",
      "wrap: bytes must be a Buffer or Uint8Array");
  }
  if (bytes.length === 0) {
    throw new ArchiveWrapError("archive-wrap/empty-input",
      "wrap: bytes is empty — nothing to seal");
  }
  if (!opts.recipient) {
    throw new ArchiveWrapError("archive-wrap/no-recipient",
      "wrap: opts.recipient is required (static key object | \"tenant\" string | peer-cert object)");
  }
  var envelope = _encryptForRecipient(bytes, opts);
  // envelope is a base64 string from b.crypto.encrypt. Buffer it and
  // prepend the 6-byte archive-wrap header so safeArchive's sniffer
  // can identify it without attempting decryption.
  var envelopeBuf = Buffer.from(envelope, "utf-8");
  var header = Buffer.alloc(ARCH_WRAP_HEADER_BYTES);
  header.write(ARCH_WRAP_MAGIC, 0, 5, "ascii");
  header[5] = ARCH_WRAP_VERSION;
  return Buffer.concat([header, envelopeBuf]);
}

/**
 * @primitive b.archive.unwrap
 * @signature b.archive.unwrap(sealed, opts)
 * @since     0.12.10
 * @status    stable
 * @related   b.archive.wrap, b.crypto.decrypt
 *
 * Recover archive bytes from a recipient-encrypted envelope produced
 * by `b.archive.wrap`. Verifies the 6-byte `BAWRP` header before
 * attempting decryption so non-envelope inputs (raw archive bytes,
 * other-magic envelopes) fail with `archive-wrap/bad-magic` rather
 * than a crypto-level error.
 *
 * @opts
 *   recipient:  object,   // { privateKey, ecPrivateKey } | { certPrivateKey, kemSecret }; required
 *
 * @example
 *   var bytes  = b.archive.unwrap(sealed, { recipient: privPair });
 *   var reader = b.archive.read.tar(b.archive.adapters.buffer(bytes));
 */
function unwrap(sealed, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(sealed) && !(sealed instanceof Uint8Array)) {
    throw new ArchiveWrapError("archive-wrap/bad-input",
      "unwrap: sealed must be a Buffer or Uint8Array");
  }
  if (sealed.length < ARCH_WRAP_HEADER_BYTES) {
    throw new ArchiveWrapError("archive-wrap/bad-magic",
      "unwrap: input shorter than 6-byte archive-wrap header");
  }
  var buf = Buffer.isBuffer(sealed) ? sealed : Buffer.from(sealed);
  var magic = buf.slice(0, 5).toString("ascii");
  if (magic !== ARCH_WRAP_MAGIC) {
    throw new ArchiveWrapError("archive-wrap/bad-magic",
      "unwrap: input does not start with archive-wrap magic " +
      JSON.stringify(ARCH_WRAP_MAGIC) + "; got " + JSON.stringify(magic));
  }
  var version = buf[5];
  if (version !== ARCH_WRAP_VERSION) {
    throw new ArchiveWrapError("archive-wrap/bad-version",
      "unwrap: archive-wrap version " + version + " not supported by this build");
  }
  if (!opts.recipient || typeof opts.recipient !== "object") {
    throw new ArchiveWrapError("archive-wrap/no-recipient",
      "unwrap: opts.recipient is required ({ privateKey, ecPrivateKey } " +
      "for the static-key path, { certPrivateKey, kemSecret } for the peer-cert path)");
  }
  var envelope = buf.slice(ARCH_WRAP_HEADER_BYTES).toString("utf-8");
  var plaintext;
  try {
    if (opts.recipient.certPrivateKey) {
      // Cert-peer path: encryptEnvelopeAsCertPeer composed
      // `encrypt(bytes, { publicKey, ecPublicKey })` where the
      // ecPublicKey was extracted from the cert. The inverse passes
      // the operator's kemSecret + certPrivateKey (P-384) through
      // the same decrypt code path. raw:true preserves binary
      // archive bytes losslessly.
      plaintext = bCrypto().decrypt(envelope, {
        privateKey:    opts.recipient.kemSecret,
        ecPrivateKey:  opts.recipient.certPrivateKey,
      }, { raw: true });
    } else {
      // raw:true returns the decrypted Buffer (lossless for arbitrary
      // binary archive payloads — utf-8 string conversion would
      // corrupt gzip / zip / tar bytes).
      plaintext = bCrypto().decrypt(envelope, opts.recipient, { raw: true });
    }
  } catch (e) {
    var err = new ArchiveWrapError("archive-wrap/decrypt-failed",
      "unwrap: envelope decryption refused: " + ((e && e.message) || String(e)));
    err.cause = e;
    throw err;
  }
  return Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
}

function _encryptForRecipient(bytes, opts) {
  var r = opts.recipient;
  if (typeof r === "string") {
    if (r === "tenant") {
      // tenant strategy lands in v0.12.11 alongside the backup
      // cryptoStrategy adoption — refuse cleanly for v0.12.10 so
      // operators see the deferred-shape contract.
      throw new ArchiveWrapError("archive-wrap/tenant-strategy-deferred",
        "wrap: recipient: \"tenant\" lands in v0.12.11 alongside b.backup cryptoStrategy: \"recipient\" + per-tenant key resolution. For v0.12.10, pass an explicit { publicKey, ecPublicKey } recipient");
    }
    throw new ArchiveWrapError("archive-wrap/bad-recipient",
      "wrap: recipient string " + JSON.stringify(r) + " not recognised; \"tenant\" deferred to v0.12.11");
  }
  if (r.peerCertDer || r.peerKemPubkey) {
    if (!r.peerCertDer || !r.peerKemPubkey) {
      throw new ArchiveWrapError("archive-wrap/bad-recipient",
        "wrap: peer-cert strategy requires BOTH peerCertDer + peerKemPubkey");
    }
    return bCrypto().encryptEnvelopeAsCertPeer(bytes, {
      peerCertDer:    r.peerCertDer,
      peerKemPubkey:  r.peerKemPubkey,
    });
  }
  if (r.publicKey) {
    return bCrypto().encrypt(bytes, {
      publicKey:    r.publicKey,
      ecPublicKey:  r.ecPublicKey,
    });
  }
  throw new ArchiveWrapError("archive-wrap/bad-recipient",
    "wrap: recipient must be { publicKey, ecPublicKey } | { peerCertDer, peerKemPubkey } | \"tenant\"");
}

function _isWrapMagic(buf) {
  return buf.length >= ARCH_WRAP_HEADER_BYTES &&
    buf.slice(0, 5).toString("ascii") === ARCH_WRAP_MAGIC;
}

module.exports = {
  wrap:             wrap,
  unwrap:           unwrap,
  ArchiveWrapError: ArchiveWrapError,
  // Exposed for sibling modules + sniffer
  _isWrapMagic:     _isWrapMagic,
  ARCH_WRAP_MAGIC:  ARCH_WRAP_MAGIC,
};
