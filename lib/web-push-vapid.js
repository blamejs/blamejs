"use strict";
/**
 * @module b.webPush
 * @nav    Networking
 * @title  Web Push (VAPID)
 * @order  240
 *
 * @intro
 *   RFC 8292 Voluntary Application Server Identification (VAPID) for
 *   Web Push (RFC 8030). Operators sign JWTs with an ECDSA-P256 key
 *   to identify themselves to the push service; the browser-side
 *   subscription includes the operator's VAPID public key in
 *   `applicationServerKey`. RFC 8292 §3 mandates ES256; the framework
 *   uses node:crypto for ECDSA because the protocol is not PQC-yet
 *   (browser push services don't accept ML-DSA today; track
 *   draft-ietf-webpush-vapid-pqc for the migration).
 *
 *   `b.webPush.buildVapidAuthHeader({ subscription, contact,
 *   privateKeyPem, publicKeyPem })` returns the `Authorization:
 *   vapid t=<jwt>, k=<base64url-pubkey>` header value the operator
 *   sets on the push-request POST to the push-service endpoint.
 *
 *   `b.webPush.generateVapidKeypair()` returns `{ publicKeyPem,
 *   privateKeyPem, publicKeyB64Url }` — the b64url-encoded public
 *   key is what the browser code passes as `applicationServerKey`.
 *
 * @card
 *   RFC 8292 VAPID JWT signer + RFC 8030 push request shape (ECDSA-P256). Operators sign once per subscription endpoint; browsers identify the push origin via the operator's public key.
 */

var nodeCrypto    = require("node:crypto");
var C             = require("./constants");
var validateOpts  = require("./validate-opts");
var safeUrl       = require("./safe-url");
var bCrypto       = require("./crypto");
var { defineClass } = require("./framework-error");

var WebPushError = defineClass("WebPushError", { alwaysPermanent: true });

/**
 * @primitive b.webPush.generateVapidKeypair
 * @signature b.webPush.generateVapidKeypair()
 * @since     0.10.16
 * @status    stable
 * @related   b.webPush.buildVapidAuthHeader
 *
 * Generate a fresh ECDSA-P256 keypair suitable for VAPID. Returns
 * `{ publicKeyPem, privateKeyPem, publicKeyB64Url }`. The b64url-
 * encoded public key is what the browser code passes as
 * `applicationServerKey` to `pushManager.subscribe`.
 *
 * @example
 *   var kp = b.webPush.generateVapidKeypair();
 *   // Browser:
 *   //   pushManager.subscribe({ applicationServerKey: kp.publicKeyB64Url })
 */
function generateVapidKeypair() {
  var kp = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve:         "prime256v1",
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  // RFC 8292 §3.2 — uncompressed point (0x04 ‖ X ‖ Y), base64url-encoded.
  var pubKeyObj = nodeCrypto.createPublicKey(kp.publicKey);
  var jwk = pubKeyObj.export({ format: "jwk" });
  var raw = Buffer.concat([
    Buffer.from([0x04]),                                                                              // allow:raw-byte-literal — uncompressed point prefix per SEC1 §2.3.3
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
  return {
    publicKeyPem:    kp.publicKey,
    privateKeyPem:   kp.privateKey,
    publicKeyB64Url: bCrypto.toBase64Url(raw),
  };
}

/**
 * @primitive b.webPush.buildVapidAuthHeader
 * @signature b.webPush.buildVapidAuthHeader(opts)
 * @since     0.10.16
 * @status    stable
 * @related   b.webPush.generateVapidKeypair
 *
 * Build the `Authorization: vapid t=<jwt>, k=<pubkey-b64url>` header
 * value per RFC 8292 §3. The JWT claims (`aud` / `exp` / `sub`) are
 * computed from the subscription endpoint origin + operator contact;
 * `exp` defaults to 12 hours (RFC 8292 §2 caps at 24 hours).
 *
 * @opts
 *   subscription:    { endpoint: string },              // browser-returned subscription
 *   contact:         string,                            // mailto:... or https:... per RFC 8292 §2
 *   privateKeyPem:   string,                            // ECDSA-P256 PEM-encoded private key
 *   publicKeyB64Url: string,                            // public key from generateVapidKeypair()
 *   ttlSec:          number,                            // optional, default 12h
 *
 * @example
 *   var hdr = b.webPush.buildVapidAuthHeader({
 *     subscription: { endpoint: "https://fcm.googleapis.com/wp/abc" },
 *     contact:      "mailto:ops@example.com",
 *     privateKeyPem:   kp.privateKeyPem,
 *     publicKeyB64Url: kp.publicKeyB64Url,
 *   });
 *   // → "vapid t=<jwt>, k=<b64url>"
 */
function buildVapidAuthHeader(opts) {
  opts = validateOpts.requireObject(opts, "webPush.buildVapidAuthHeader",
    WebPushError, "web-push/bad-opts");
  validateOpts(opts, ["subscription", "contact", "privateKeyPem",
                       "publicKeyB64Url", "ttlSec"],
    "webPush.buildVapidAuthHeader");
  if (!opts.subscription || typeof opts.subscription.endpoint !== "string") {
    throw new WebPushError("web-push/bad-subscription",
      "buildVapidAuthHeader: opts.subscription must include a string endpoint");
  }
  validateOpts.requireNonEmptyString(opts.contact, "contact",
    WebPushError, "web-push/bad-contact");
  if (!/^(mailto:|https:)/i.test(opts.contact)) {
    throw new WebPushError("web-push/bad-contact",
      "buildVapidAuthHeader: contact must start with 'mailto:' or 'https:' per RFC 8292 §2");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem, "privateKeyPem",
    WebPushError, "web-push/bad-key");
  validateOpts.requireNonEmptyString(opts.publicKeyB64Url, "publicKeyB64Url",
    WebPushError, "web-push/bad-key");
  validateOpts.optionalPositiveFinite(opts.ttlSec, "webPush.buildVapidAuthHeader: ttlSec",
    WebPushError, "web-push/bad-ttl");
  var ttlSec = opts.ttlSec || C.TIME.hours(12);
  // Audience: origin of the subscription endpoint per RFC 8292 §2.
  var endpointUrl;
  try { endpointUrl = safeUrl.parse(opts.subscription.endpoint); }
  catch (_e) {
    throw new WebPushError("web-push/bad-endpoint",
      "buildVapidAuthHeader: subscription.endpoint is not a parseable URL");
  }
  var aud = endpointUrl.origin;
  var now = Math.floor(Date.now() / 1000);                                                            // allow:raw-time-literal — wall-clock seconds for JWT exp
  // Inline JWT sign with ES256 — VAPID strictly mandates ECDSA-P256
  // (RFC 8292 §3.1). The framework jwt.sign is PQC-first and refuses
  // ES256 by design; VAPID is a wire-protocol constraint outside
  // that policy. b.webPush owns the ES256 signing inline so the
  // framework's broader PQC posture remains intact.
  var header  = { typ: "JWT", alg: "ES256" };
  var payload = { aud: aud, exp: now + ttlSec, sub: opts.contact };
  var headerB64  = bCrypto.toBase64Url(Buffer.from(JSON.stringify(header), "utf8"));
  var payloadB64 = bCrypto.toBase64Url(Buffer.from(JSON.stringify(payload), "utf8"));
  var signingInput = headerB64 + "." + payloadB64;
  var keyObj = nodeCrypto.createPrivateKey(opts.privateKeyPem);
  if (keyObj.asymmetricKeyType !== "ec") {
    throw new WebPushError("web-push/bad-key",
      "buildVapidAuthHeader: privateKeyPem must be an ECDSA-P256 key (RFC 8292 §3.1)");
  }
  // node:crypto produces DER-encoded ECDSA signature; JWT ES256
  // requires the raw 64-byte r||s shape. Convert.
  var derSig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "utf8"), keyObj);
  var rawSig = _ecdsaDerToRaw(derSig, 32);                                                            // allow:raw-byte-literal — 32-byte P-256 component
  var token = signingInput + "." + bCrypto.toBase64Url(rawSig);
  return "vapid t=" + token + ", k=" + opts.publicKeyB64Url;
}

function _ecdsaDerToRaw(der, componentLen) {
  // ECDSA-Sig-Value DER = SEQUENCE { r INTEGER, s INTEGER }.
  if (der[0] !== 0x30) {                                                                              // allow:raw-byte-literal — ASN.1 SEQUENCE tag
    throw new WebPushError("web-push/bad-sig",
      "ECDSA signature is not a DER SEQUENCE");
  }
  var off = 2;
  if (der[1] & 0x80) off = 2 + (der[1] & 0x7f);                                                       // allow:raw-byte-literal — long-form length byte
  if (der[off] !== 0x02) throw new WebPushError("web-push/bad-sig", "missing r INTEGER");             // allow:raw-byte-literal — ASN.1 INTEGER tag
  var rLen = der[off + 1];
  var rStart = off + 2;
  var r = der.slice(rStart, rStart + rLen);
  off = rStart + rLen;
  if (der[off] !== 0x02) throw new WebPushError("web-push/bad-sig", "missing s INTEGER");             // allow:raw-byte-literal — ASN.1 INTEGER tag
  var sLen = der[off + 1];
  var sStart = off + 2;
  var s = der.slice(sStart, sStart + sLen);
  // Trim leading zero pad (DER requires it when high bit set; JWT raw doesn't).
  if (r.length > componentLen && r[0] === 0x00) r = r.slice(1);                                        // allow:raw-byte-literal — DER sign-bit pad
  if (s.length > componentLen && s[0] === 0x00) s = s.slice(1);                                        // allow:raw-byte-literal — DER sign-bit pad
  var out = Buffer.alloc(componentLen * 2);
  r.copy(out, componentLen - r.length);
  s.copy(out, componentLen * 2 - s.length);
  return out;
}

module.exports = {
  generateVapidKeypair:     generateVapidKeypair,
  buildVapidAuthHeader:     buildVapidAuthHeader,
  WebPushError:             WebPushError,
};
