"use strict";
/**
 * @module     b.mail.crypto
 * @featured   false
 * @nav        Communication
 * @title      Mail crypto (PGP + S/MIME)
 * @order      119
 * @slug       mail-crypto
 *
 * @intro
 *   End-to-end mail signing + verification, organized into two sub-
 *   namespaces by wire format:
 *
 *     - `b.mail.crypto.pgp` — OpenPGP per RFC 9580 (November 2024),
 *       wrapped in `multipart/signed; protocol="application/pgp-
 *       signature"` per RFC 3156. v1 surface: sign() + verify() with
 *       v4 detached signatures over Ed25519 (pub-alg 22) and RSA
 *       (pub-alg 1, EMSA-PKCS1-v1_5 + SHA-256, 2048-bit floor per
 *       RFC 8301).
 *     - `b.mail.crypto.smime` — S/MIME 4.0 per RFC 8551 with CMS
 *       SignedData per RFC 5652. v1 surface: checkCert() — the
 *       operator-side preflight that refuses SHA-1 / MD5 / < 2048-bit
 *       RSA certs at boot. sign() + verify() are DEFERRED in v1; see
 *       the @intro block in lib/mail-crypto-smime.js for the deferral
 *       conditions and the operator escape hatch.
 *
 *   Both sub-namespaces share `MailCryptoError` (FrameworkError
 *   subclass via defineClass with alwaysPermanent: true) so operator
 *   error handling can `catch (e) { if (e instanceof
 *   b.mail.crypto.MailCryptoError) ... }` once and cover both
 *   protocols.
 *
 *   Composition with the rest of the mail surface:
 *     - DKIM-Signature (b.mail.dkim) signs at the SMTP-message
 *       transport boundary; PGP / S/MIME sign at the user-visible
 *       payload boundary. The two are complementary — a message can
 *       carry BOTH a DKIM-Signature header (proving the sending
 *       domain) AND a PGP / S/MIME signature (proving the human
 *       sender's key). Operators wiring both wire DKIM via
 *       `opts.dkimSigner` on the smtp transport and call
 *       `b.mail.crypto.pgp.sign()` over the multipart body before
 *       handing it to the transport.
 *     - When the EFAIL-class encrypt/decrypt surface lights up (see
 *       per-sub-namespace deferral conditions), rendered HTML routes
 *       through `b.guardHtml` strict profile and the MIME-part tree
 *       is captured at decrypt time + diffed against the tree at
 *       render time.
 *
 *   This top-level module is a thin re-export — the actual surface
 *   lives in lib/mail-crypto-pgp.js and lib/mail-crypto-smime.js.
 *
 * @primitive  b.mail.crypto.pgp
 * @primitive  b.mail.crypto.smime
 * @since      0.9.58
 * @status     experimental
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.dkim, b.mail.arc, b.guardEmail, b.guardHtml
 *
 * RFC citations:
 *   - RFC 9580 (OpenPGP, Nov 2024; obsoletes RFC 4880)
 *   - RFC 3156 (MIME Security with OpenPGP)
 *   - RFC 8551 (S/MIME 4.0 Message Specification; obsoletes RFC 5751)
 *   - RFC 5652 (Cryptographic Message Syntax)
 *   - RFC 8550 (S/MIME 4.0 Certificate Handling)
 *
 * CVE citations:
 *   - CVE-2017-17688 / CVE-2017-17689 (EFAIL)
 *   - CVE-2017-9006 (PKCS#7 / S/MIME signature-validation bypass class)
 */

var pgp   = require("./mail-crypto-pgp");
var smime = require("./mail-crypto-smime");

// Both sub-modules define `MailCryptoError` independently (each via
// `defineClass("MailCryptoError", { alwaysPermanent: true })`) — at
// runtime they are distinct classes. The facade re-exports the PGP
// one and provides `isMailCryptoError(e)` for the cross-protocol
// shape check that doesn't depend on class identity. Both classes
// extend FrameworkError and both set the `isMailCryptoError = true`
// flag, so the duck-type check is reliable across the boundary.
var MailCryptoError = pgp.MailCryptoError;

function isMailCryptoError(e) {
  return !!(e && e.isMailCryptoError === true);
}

module.exports = {
  pgp:               pgp,
  smime:             smime,
  MailCryptoError:   MailCryptoError,
  isMailCryptoError: isMailCryptoError,
};
