"use strict";
/**
 * Passphrase source drivers — env / file / stdin.
 *
 * Single interface: `getPassphrase(opts)` returns a Promise<Buffer>. Buffers
 * (not strings) preserve byte-exactness for binary passphrases and avoid
 * accidental intermediate string allocations that linger in the heap.
 *
 * Selected via `BLAMEJS_VAULT_PASSPHRASE_SOURCE` env var:
 *   (unset|auto)  — priority order: BLAMEJS_VAULT_PASSPHRASE_FILE,
 *                                   BLAMEJS_VAULT_PASSPHRASE, stdin
 *   env           — require BLAMEJS_VAULT_PASSPHRASE
 *   file          — require BLAMEJS_VAULT_PASSPHRASE_FILE
 *   stdin         — require a TTY on stdin
 *
 * After reading the env source, `delete process.env.BLAMEJS_VAULT_PASSPHRASE`
 * limits exposure to later env-dump surfaces. This doesn't zero the memory
 * (JavaScript can't) but does remove the env-object reference.
 */
var fs = require("fs");

var MAX_PASSPHRASE_BYTES = 4096;

var ENV_PASSPHRASE       = "BLAMEJS_VAULT_PASSPHRASE";
var ENV_PASSPHRASE_FILE  = "BLAMEJS_VAULT_PASSPHRASE_FILE";
var ENV_PASSPHRASE_SRC   = "BLAMEJS_VAULT_PASSPHRASE_SOURCE";

function stripEnvVar() {
  if (ENV_PASSPHRASE in process.env) {
    delete process.env[ENV_PASSPHRASE];
  }
}

function trimTrailingNewlines(buf) {
  var end = buf.length;
  while (end > 0) {
    var b = buf[end - 1];
    if (b === 0x0A || b === 0x0D) end--;
    else break;
  }
  return end === buf.length ? buf : buf.subarray(0, end);
}

function validatePassphraseBuffer(buf, contextLabel) {
  if (!buf || buf.length === 0) {
    throw new Error(contextLabel + ": passphrase is empty");
  }
  if (buf.length > MAX_PASSPHRASE_BYTES) {
    throw new Error(contextLabel + ": passphrase exceeds " + MAX_PASSPHRASE_BYTES + " byte sanity limit");
  }
}

async function fromEnv() {
  var val = process.env[ENV_PASSPHRASE];
  if (val === undefined || val === null || val === "") {
    throw new Error(ENV_PASSPHRASE + " env var is not set or is empty");
  }
  var buf = Buffer.from(val, "utf8");
  validatePassphraseBuffer(buf, "env source");
  stripEnvVar();
  return buf;
}

async function fromFile(filePath) {
  if (!filePath) {
    throw new Error(ENV_PASSPHRASE_FILE + " is not set");
  }
  var raw;
  try {
    raw = fs.readFileSync(filePath);
  } catch (e) {
    throw new Error("failed to read " + ENV_PASSPHRASE_FILE + " (" + filePath + "): " + e.code);
  }
  var buf = trimTrailingNewlines(raw);
  validatePassphraseBuffer(buf, "file source (" + filePath + ")");
  return buf;
}

async function fromStdin(promptText) {
  if (!process.stdin.isTTY) {
    throw new Error("stdin passphrase source requires a TTY (use `docker run -it` or similar)");
  }
  var readline = require("readline");
  promptText = promptText || "Vault passphrase: ";

  return new Promise(function (resolve, reject) {
    var rl = readline.createInterface({
      input:    process.stdin,
      output:   process.stdout,
      terminal: true,
    });
    process.stdout.write(promptText);

    var chunks = [];

    var onData = function (chunk) {
      for (var i = 0; i < chunk.length; i++) {
        var b = chunk[i];
        if (b === 0x03) { // ctrl-C
          cleanup();
          process.stdout.write("\n");
          reject(new Error("passphrase input cancelled"));
          return;
        }
        if (b === 0x0A || b === 0x0D) { // enter
          cleanup();
          process.stdout.write("\n");
          var buf = Buffer.concat(chunks);
          try {
            validatePassphraseBuffer(buf, "stdin source");
            resolve(buf);
          } catch (e) {
            reject(e);
          }
          return;
        }
        if (b === 0x7F || b === 0x08) { // backspace / DEL
          if (chunks.length > 0) chunks.pop();
          continue;
        }
        chunks.push(Buffer.from([b]));
      }
    };

    var cleanup = function () {
      try { process.stdin.setRawMode(false); } catch (_e) { /* best effort */ }
      process.stdin.removeListener("data", onData);
      rl.close();
    };

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

function sourceKind() {
  var mode = (process.env[ENV_PASSPHRASE_SRC] || "auto").toLowerCase();
  if (mode === "auto") {
    if (process.env[ENV_PASSPHRASE_FILE]) return "file";
    if (process.env[ENV_PASSPHRASE]) return "env";
    if (process.stdin.isTTY) return "stdin";
    return null;
  }
  if (mode === "env" || mode === "file" || mode === "stdin") return mode;
  throw new Error("Unknown " + ENV_PASSPHRASE_SRC + ": " + mode + " (expected auto, env, file, or stdin)");
}

async function getPassphrase(opts) {
  opts = opts || {};
  var kind = sourceKind();
  if (!kind) {
    throw new Error(
      "No passphrase source available. Set one of: " +
      ENV_PASSPHRASE + ", " + ENV_PASSPHRASE_FILE + ", " +
      "or run with a TTY on stdin."
    );
  }
  if (kind === "env")   return fromEnv();
  if (kind === "file")  return fromFile(process.env[ENV_PASSPHRASE_FILE]);
  if (kind === "stdin") return fromStdin(opts.prompt);
  throw new Error("Unreachable: unknown passphrase source kind " + kind);
}

module.exports = {
  getPassphrase:        getPassphrase,
  sourceKind:           sourceKind,
  fromEnv:              fromEnv,
  fromFile:             fromFile,
  fromStdin:            fromStdin,
  MAX_PASSPHRASE_BYTES: MAX_PASSPHRASE_BYTES,
  // Env var names exposed for documentation/testing
  ENV_PASSPHRASE:       ENV_PASSPHRASE,
  ENV_PASSPHRASE_FILE:  ENV_PASSPHRASE_FILE,
  ENV_PASSPHRASE_SRC:   ENV_PASSPHRASE_SRC,
};
