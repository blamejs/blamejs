"use strict";
/**
 * vendor-data-keygen.js — one-time generation of the maintainer
 * vendor-data signing keypair (SLH-DSA-SHAKE-256f).
 *
 * The PRIVATE key is written to `.keys/vendor-data-private.pem`
 * (gitignored — never committed). The PUBLIC key is written to
 * `lib/vendor/.vendor-data-pubkey` (committed; ships in every npm
 * tarball; the trust root every operator's verifier consults).
 *
 * Once generated, NEVER re-run this script — re-running rotates the
 * key and invalidates every previously-signed `.data.js`. Key
 * rotation requires re-signing every vendor data file via
 * scripts/vendor-update.sh --refresh-data and shipping the new
 * pubkey in the next release. Document rotation rationale in
 * CHANGELOG.md.
 */

var fs = require("fs");
var path = require("path");
var pqcSoftware = require("../lib/pqc-software");

var KEYS_DIR = path.resolve(__dirname, "..", ".keys");
var VENDOR_PUBKEY = path.resolve(__dirname, "..", "lib", "vendor", ".vendor-data-pubkey");
var PRIV_PATH = path.join(KEYS_DIR, "vendor-data-private.pem");
var PUB_PATH_LOCAL = path.join(KEYS_DIR, "vendor-data-public.pem");

if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
}

var slh = pqcSoftware.slh_dsa_shake_256f;
var pair = slh.keygen();   // { publicKey: Uint8Array, secretKey: Uint8Array }

function toPem(label, raw) {
  var b64 = Buffer.from(raw).toString("base64");
  var wrapped = b64.match(/.{1,64}/g).join("\n");
  return "-----BEGIN " + label + "-----\n" + wrapped + "\n-----END " + label + "-----\n";
}

// Atomic create — `wx` flag opens-or-fails-with-EEXIST without a
// time-of-check-time-of-use window (CodeQL js/file-system-race
// defense). If --force is passed, we open with `w` which truncates;
// the explicit overwrite is the operator's intent.
var forceRotate = process.argv.includes("--force");
var flag = forceRotate ? "w" : "wx";

function writeFileExclusive(p, contents, mode) {
  try {
    var fd = fs.openSync(p, flag, mode);
    try { fs.writeSync(fd, contents); } finally { fs.closeSync(fd); }
  } catch (e) {
    if (e && e.code === "EEXIST") {
      process.stderr.write("vendor-data-keygen: " + p + " already exists. " +
                           "Pass --force to ROTATE (invalidates all signed " +
                           ".data.js files; ship new pubkey + re-sign every " +
                           "vendor file).\n");
      process.exit(2);
    }
    throw e;
  }
}

writeFileExclusive(PRIV_PATH, toPem("SLH-DSA-SHAKE-256F PRIVATE KEY", pair.secretKey), 0o600);
writeFileExclusive(PUB_PATH_LOCAL, toPem("SLH-DSA-SHAKE-256F PUBLIC KEY", pair.publicKey), 0o644);
writeFileExclusive(VENDOR_PUBKEY, toPem("SLH-DSA-SHAKE-256F PUBLIC KEY", pair.publicKey), 0o644);

process.stdout.write("✓ private key written to " + PRIV_PATH + " (mode 0600, NEVER commit)\n");
process.stdout.write("✓ public key  written to " + PUB_PATH_LOCAL + " (local copy for reference)\n");
process.stdout.write("✓ public key  committed at " + VENDOR_PUBKEY + " (ships in npm tarball)\n");
process.stdout.write("\n");
process.stdout.write("Next: run `scripts/vendor-update.sh --refresh-data` to (re)sign every\n");
process.stdout.write("vendor data file against this new key. Then commit the regenerated\n");
process.stdout.write(".data.js files + the new .vendor-data-pubkey alongside the release.\n");
