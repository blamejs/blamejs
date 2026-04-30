"use strict";
/**
 * mtls-ca — mTLS Certificate Authority management.
 *
 * Storage, sealed-loading dispatch, generation tagging, atomic commit.
 * Cert issuance (CA generation, client cert signing, PKCS#12 packaging)
 * delegates to a pluggable engine. The framework ships a default
 * pure-JS engine (lib/mtls-engine-default.js, backed by the vendored
 * @peculiar/x509 + pkijs bundle); operators with custom requirements
 * pass their own via opts.engine.
 *
 *   var ca = b.mtlsCa.create({
 *     dataDir:          "./data",
 *     paths: {
 *       caKey:          "ca.key",
 *       caKeySealed:    "ca.key.sealed",
 *       caCert:         "ca.crt",
 *     },
 *     vault:            b.vault,         // optional; required when sealed
 *     caKeySealedMode:  "auto",          // "auto" | "required" | "disabled"
 *     generation:       1,               // current CA generation for OU=CAv{N}
 *     engine:           myCertEngine,    // optional — defaults to b.mtlsEngine
 *   });
 *
 * Files (relative to dataDir):
 *   ca.crt           CA certificate (PEM, plaintext on disk)
 *   ca.key           CA private key (PEM, plaintext on disk)
 *   ca.key.sealed    CA private key (vault.seal of PEM bytes)
 *
 * caKeySealedMode:
 *   "auto"      load whichever exists (sealed if present, else plain)
 *   "required"  sealed file required; refuse plaintext
 *   "disabled"  plaintext required; refuse sealed
 *
 * Generation tagging: every CA cert issued by the framework embeds a
 * "OU=CAv{N}" RDN in its subject DN. Status reads that back so an
 * upgrade flow can detect legacy CAs (a pre-rotation CA whose key
 * parameters are below the current bar) and prompt regeneration
 * without breaking active mTLS clients.
 *
 * Issuance surface (delegates to opts.engine):
 *
 *   ca.initCA()
 *     returns existing { caCertPem, caKeyPem } or generates a fresh
 *     pair via engine.generateCa() and atomically commits it.
 *
 *   ca.generateClientCert({ cn, validityDays })
 *     calls engine.signClientCert with the CA loaded.
 *
 *   ca.generateClientP12({ cn, password, validityDays })
 *     calls engine.packageP12 with the CA loaded.
 *
 * Engine contract (default lib/mtls-engine-default.js, override via
 * opts.engine):
 *
 *   {
 *     async generateCa({ generation })
 *       returns { caCertPem, caKeyPem },
 *     async signClientCert({ cn, validityDays, caCertPem, caKeyPem })
 *       returns { cert, key, ca, issuedAt, expiresAt },
 *     async packageP12({ cn, password, validityDays, caCertPem, caKeyPem })
 *       returns { p12, certPem, issuedAt, expiresAt },
 *   }
 *
 * Note: the engine returns the cert PEM (`certPem`) but does NOT
 * compute a fingerprint — the framework hashes the cert via
 * `b.crypto.sha3Hash(certPem)` for any audit / display purpose,
 * keeping the SHA3-512 posture consistent across the rest of the
 * stack. Operators who want the X.509-conventional SHA-256
 * fingerprint (for browser cert-details panels, openssl interop)
 * compute it separately from the cert PEM.
 */

var fs = require("fs");
var path = require("path");
var nodeCrypto = require("node:crypto");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

class MtlsCaError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "MtlsCaError";
    this.permanent = true;
    this.isMtlsCaError = true;
  }
}

var DEFAULT_PATHS = {
  caKey:        "ca.key",
  caKeySealed:  "ca.key.sealed",
  caCert:       "ca.crt",
};

var VALID_SEAL_MODES = { auto: 1, required: 1, disabled: 1 };

function _resolvePaths(dataDir, paths) {
  var p = Object.assign({}, DEFAULT_PATHS, paths || {});
  return {
    caKey:        path.join(dataDir, p.caKey),
    caKeySealed:  path.join(dataDir, p.caKeySealed),
    caCert:       path.join(dataDir, p.caCert),
  };
}

// Parse "OU=CAv{N}" from a PEM cert's subject DN. Returns the integer
// N (defaulting to 1 for untagged legacy CAs) or 0 when the cert is
// unreadable. Untagged returning 1 means the first regen lifts a legacy
// CA to generation 2 without misidentifying it as fresh.
function parseGeneration(certPem) {
  if (typeof certPem !== "string" && !Buffer.isBuffer(certPem)) return 0;
  try {
    var cert = new nodeCrypto.X509Certificate(certPem);
    var subj = cert.subject || "";
    var m = /OU=CAv(\d+)/.exec(subj);
    return m ? parseInt(m[1], 10) : 1;
  } catch (_e) {
    return 0;
  }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "paths", "vault",
    "caKeySealedMode", "generation", "engine",
  ], "b.mtlsCa");
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new MtlsCaError("mtls-ca/no-datadir",
      "mtlsCa.create requires opts.dataDir");
  }
  var paths = _resolvePaths(opts.dataDir, opts.paths);
  var vault = opts.vault || null;
  var caKeySealedMode = (opts.caKeySealedMode || "auto").toLowerCase();
  if (!VALID_SEAL_MODES[caKeySealedMode]) {
    throw new MtlsCaError("mtls-ca/bad-mode",
      "caKeySealedMode must be 'auto', 'required', or 'disabled'");
  }
  var generation = typeof opts.generation === "number" && opts.generation >= 1
    ? Math.floor(opts.generation) : 1;
  // The default engine carries a 600+ KB vendored bundle; load it only
  // when operators rely on it (no custom engine passed). Operators who
  // wire their own engine never pay the cost.
  var engine = opts.engine || require("./mtls-engine-default");

  function _requireVault(reason) {
    if (!vault || typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
      throw new MtlsCaError("mtls-ca/no-vault",
        reason + " requires opts.vault (with seal/unseal). Pass b.vault " +
        "or use caKeySealedMode='disabled' to keep the CA key on disk in plaintext.");
    }
  }

  function keyExists() {
    return fs.existsSync(paths.caKey) || fs.existsSync(paths.caKeySealed);
  }
  function exists() {
    return keyExists() && fs.existsSync(paths.caCert);
  }

  function status() {
    if (!exists()) {
      return {
        exists:     false,
        generation: 0,
        isLegacy:   false,
        current:    generation,
      };
    }
    var pem = fs.readFileSync(paths.caCert);
    var gen = parseGeneration(pem);
    return {
      exists:     true,
      generation: gen,
      isLegacy:   gen < generation,
      current:    generation,
    };
  }

  // Load the CA key in whichever form is on disk, applying the
  // caKeySealedMode dispatch. Returns Buffer of PEM bytes, or throws
  // with a precise reason when the mode rejects the on-disk form.
  function loadKey() {
    var hasPlain  = fs.existsSync(paths.caKey);
    var hasSealed = fs.existsSync(paths.caKeySealed);
    if (!hasPlain && !hasSealed) {
      throw new MtlsCaError("mtls-ca/missing-key",
        "no CA key on disk at " + paths.caKey + " or " + paths.caKeySealed);
    }
    if (caKeySealedMode === "required") {
      if (!hasSealed) {
        throw new MtlsCaError("mtls-ca/sealed-required",
          "CA_KEY_SEALED='required' but " + paths.caKeySealed + " does not exist");
      }
      _requireVault("sealed CA key load");
      var sealedBytes = fs.readFileSync(paths.caKeySealed, "utf8").trim();
      var pem = vault.unseal(sealedBytes);
      if (!pem) {
        throw new MtlsCaError("mtls-ca/unseal-failed",
          "vault.unseal of " + paths.caKeySealed + " returned empty — vault key mismatch?");
      }
      return Buffer.from(pem, "utf8");
    }
    if (caKeySealedMode === "disabled") {
      if (!hasPlain) {
        throw new MtlsCaError("mtls-ca/plain-required",
          "CA_KEY_SEALED='disabled' but " + paths.caKey + " does not exist");
      }
      return fs.readFileSync(paths.caKey);
    }
    // auto: prefer sealed if it exists (defense-in-depth default)
    if (hasSealed) {
      _requireVault("sealed CA key load");
      var sealedBytesA = fs.readFileSync(paths.caKeySealed, "utf8").trim();
      var pemA = vault.unseal(sealedBytesA);
      if (!pemA) {
        throw new MtlsCaError("mtls-ca/unseal-failed",
          "vault.unseal of " + paths.caKeySealed + " returned empty");
      }
      return Buffer.from(pemA, "utf8");
    }
    return fs.readFileSync(paths.caKey);
  }

  function loadCert() {
    if (!fs.existsSync(paths.caCert)) {
      throw new MtlsCaError("mtls-ca/missing-cert",
        "no CA cert on disk at " + paths.caCert);
    }
    return fs.readFileSync(paths.caCert);
  }

  // Atomic commit: write .tmp + atomic rename for both key and cert.
  // Honors caKeySealedMode — when 'required', the key is vault-sealed
  // before the on-disk write so plaintext PEM never touches the
  // filesystem; when 'disabled', it goes to disk as PEM. 'auto'
  // defaults to plaintext-on-disk.
  function commit(opts2) {
    if (!opts2 || typeof opts2.caKeyPem !== "string" || typeof opts2.caCertPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-commit",
        "commit requires opts.caKeyPem and opts.caCertPem (PEM strings)");
    }
    var sealed = caKeySealedMode === "required";
    var keyDest = sealed ? paths.caKeySealed : paths.caKey;
    var keyTmp = keyDest + ".tmp";
    var certTmp = paths.caCert + ".tmp";

    try {
      if (sealed) {
        _requireVault("sealed CA key commit");
        fs.writeFileSync(keyTmp, vault.seal(opts2.caKeyPem), { mode: 0o600 });
      } else {
        fs.writeFileSync(keyTmp, opts2.caKeyPem, { mode: 0o600 });
      }
      fs.writeFileSync(certTmp, opts2.caCertPem, { mode: 0o644 });
      fs.renameSync(keyTmp, keyDest);
      fs.renameSync(certTmp, paths.caCert);
    } catch (e) {
      try { if (fs.existsSync(keyTmp))  fs.unlinkSync(keyTmp); }  catch (_e) {}
      try { if (fs.existsSync(certTmp)) fs.unlinkSync(certTmp); } catch (_e) {}
      throw new MtlsCaError("mtls-ca/commit-failed",
        "atomic CA commit failed: " + ((e && e.message) || String(e)));
    }
    return {
      keyPath:  keyDest,
      certPath: paths.caCert,
      sealed:   sealed,
    };
  }

  async function initCA() {
    if (exists()) {
      return { caCertPem: loadCert().toString("utf8"), caKeyPem: loadKey().toString("utf8") };
    }
    var fresh = await engine.generateCa({ generation: generation });
    if (!fresh || typeof fresh.caCertPem !== "string" || typeof fresh.caKeyPem !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.generateCa must return { caCertPem, caKeyPem }");
    }
    commit(fresh);
    return fresh;
  }

  async function generateClientCert(opts2) {
    opts2 = opts2 || {};
    var ca = await initCA();
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    var result = await engine.signClientCert(args);
    if (!result || typeof result.cert !== "string" || typeof result.key !== "string") {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.signClientCert must return { cert, key, ca?, issuedAt?, expiresAt? }");
    }
    return result;
  }

  async function generateClientP12(opts2) {
    opts2 = opts2 || {};
    if (!opts2.password || typeof opts2.password !== "string") {
      throw new MtlsCaError("mtls-ca/no-password",
        "generateClientP12 requires opts.password (the PKCS#12 encryption password)");
    }
    var ca = await initCA();
    var args = Object.assign({}, opts2, { caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem });
    var result = await engine.packageP12(args);
    if (!result || !Buffer.isBuffer(result.p12)) {
      throw new MtlsCaError("mtls-ca/bad-engine-output",
        "engine.packageP12 must return { p12: Buffer, certPem, issuedAt, expiresAt }");
    }
    return result;
  }

  return {
    exists:               exists,
    keyExists:            keyExists,
    status:               status,
    loadKey:              loadKey,
    loadCert:             loadCert,
    commit:               commit,
    initCA:               initCA,
    generateClientCert:   generateClientCert,
    generateClientP12:    generateClientP12,
    paths:                paths,
    generation:           generation,
    caKeySealedMode:      caKeySealedMode,
  };
}

module.exports = {
  create:           create,
  parseGeneration:  parseGeneration,
  MtlsCaError:      MtlsCaError,
  DEFAULT_PATHS:    DEFAULT_PATHS,
};
