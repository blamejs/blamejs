"use strict";
// Build a CycloneDX 1.6 SBOM covering lib/vendor/* bundles.
//
// Run via:
//   node scripts/build-vendored-sbom.js > sbom.vendored.cdx.json
//
// Wired into .github/workflows/npm-publish.yml. The primary SBOM
// (sbom.cdx.json) describes the npm package's (empty) runtime deps;
// this doc describes the actual code shipping inside the tarball.

var fs       = require("node:fs");
var path     = require("node:path");
var crypto   = require("node:crypto");

var manifestPath = path.resolve(__dirname, "..", "lib", "vendor", "MANIFEST.json");
var manifest;
try {
  var raw = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  // MANIFEST.json shape: { _comment, packages: { key: entry, ... } }
  manifest = raw.packages || raw;
} catch (e) {
  process.stderr.write("[build-vendored-sbom] failed to read MANIFEST.json: " + e.message + "\n");
  process.exit(1);
}

var rootPkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "package.json"), "utf8"));

// SUPPLY-12 — CycloneDX 1.6 §4.2 requires serialNumber to be a UUID
// uniquely identifying the BOM artifact. Deriving the UUID from the
// rootPkg.version made every rebuild of the SAME version produce the
// same serialNumber — BOM-diff tools (Dependency-Track, Snyk SBOM
// Monitor) couldn't distinguish rebuilds that should be independent
// artifacts (different timestamps, different lifecycles). Switch to
// crypto.randomUUID() per invocation; downstream consumers rely on
// serialNumber-per-build identity, not version-stable identity.
var serialNumber = "urn:uuid:" + crypto.randomUUID();

// SUPPLY-15 — CycloneDX 1.6 §4.4 (metadata.supplier) + SLSA v1.0
// provenance attestation require a `supplier` block on every BOM the
// build pipeline emits. `gh attestation verify` walks the chain and
// fails closed when the SBOM omits metadata.supplier. The supplier
// for blamejs framework artifacts is the framework maintainer
// publisher identity.
var FRAMEWORK_SUPPLIER = {
  "name": "blamejs",
  "url":  ["https://blamejs.com/"],
};

// SUPPLY-22 — CycloneDX 1.6 §4.4.2 — metadata.lifecycles[] entries
// MAY carry externalReferences pointing at the build pipeline that
// produced this BOM. Provenance walkers (Sigstore, SLSA verifiers)
// reach for these when correlating the BOM to its build run.
// GITHUB_SERVER_URL + GITHUB_REPOSITORY + GITHUB_RUN_ID are populated
// by Actions; absent locally the externalRef is omitted.
function _githubActionsRunUrl() {
  var server = process.env.GITHUB_SERVER_URL;                       // allow:raw-process-env — read by env-driven script
  var repo   = process.env.GITHUB_REPOSITORY;                       // allow:raw-process-env — read by env-driven script
  var runId  = process.env.GITHUB_RUN_ID;                           // allow:raw-process-env — read by env-driven script
  if (typeof server === "string" && server.length > 0 &&
      typeof repo === "string" && repo.length > 0 &&
      typeof runId === "string" && runId.length > 0) {
    return server + "/" + repo + "/actions/runs/" + runId;
  }
  return null;
}

// SUPPLY-14 — CycloneDX 1.6 §4.6 — license.id MUST be a valid SPDX
// license-list identifier. Non-SPDX prose ("BIMI Group / per-issuer")
// falls into license.name (the free-text fallback) so consumers
// parsing SBOM-as-SPDX don't reject the whole BOM on an unknown
// identifier. Keep the validator narrow — full SPDX list has
// hundreds of entries; we cover the common SPDX identifiers used by
// the framework's vendored deps, then anything else routes to
// license.name with `license_is_spdx: false` honoring the manifest's
// explicit override.
var SPDX_LICENSE_IDS = Object.freeze({
  "0BSD": 1, "Apache-2.0": 1, "BSD-2-Clause": 1, "BSD-3-Clause": 1,
  "CC0-1.0": 1, "CC-BY-3.0": 1, "CC-BY-4.0": 1, "CC-BY-SA-4.0": 1,
  "GPL-2.0-only": 1, "GPL-2.0-or-later": 1, "GPL-3.0-only": 1,
  "GPL-3.0-or-later": 1, "LGPL-2.1-only": 1, "LGPL-2.1-or-later": 1,
  "LGPL-3.0-only": 1, "LGPL-3.0-or-later": 1, "ISC": 1, "MIT": 1,
  "MIT-0": 1, "MPL-2.0": 1, "Unlicense": 1, "WTFPL": 1, "Zlib": 1,
});

function _licenseFor(entry) {
  if (typeof entry.license !== "string" || entry.license.length === 0) return null;
  // Operator-explicit non-SPDX flag takes precedence.
  if (entry.license_is_spdx === false) {
    return [{ license: { name: entry.license } }];
  }
  // SPDX identifier check — license-list match goes to `id`, free text
  // to `name`. Spec-conformant SBOM consumers reject license.id =
  // "BIMI Group / per-issuer" since it isn't on the SPDX list.
  if (SPDX_LICENSE_IDS[entry.license]) {
    return [{ license: { id: entry.license } }];
  }
  return [{ license: { name: entry.license } }];
}

function _purlFor(entry, key) {
  // Manifest key IS the npm package name for npm-mapped entries.
  if (/^(@[a-z0-9-_.]+\/)?[a-z0-9-_.]+$/i.test(key) && entry.source && /npm|github\.com\//.test(entry.source)) {
    // If source looks like a github repo, prefer pkg:github
    if (/^https?:\/\/github\.com\//.test(entry.source)) {
      var m = /^https?:\/\/github\.com\/([^/]+)\/([^/]+)/.exec(entry.source);
      if (m && !/^@/.test(key)) {
        // Use github purl when not a scoped npm package
        return "pkg:github/" + m[1] + "/" + m[2].replace(/\.git$/, "") +
               "@" + entry.version;
      }
    }
    return "pkg:npm/" + key.replace(/^@/, "%40").replace("/", "%2F") +
           "@" + entry.version;
  }
  return "pkg:generic/" + key + "@" + entry.version;
}

function _hashesFor(entry) {
  var rv = [];
  if (entry.sha256) {
    rv.push({ alg: "SHA-256", content: entry.sha256 });
    return rv;
  }
  // MANIFEST.json shape: hashes: { server: "sha256:<hex>", ... }
  if (entry.hashes && typeof entry.hashes === "object") {
    Object.keys(entry.hashes).forEach(function (slot) {
      var v = entry.hashes[slot];
      if (typeof v !== "string") return;
      var m = /^sha256:([a-f0-9]{64})$/i.exec(v);
      if (m) rv.push({ alg: "SHA-256", content: m[1] });
    });
  }
  return rv;
}

var components = Object.keys(manifest).filter(function (key) {
  // Skip MANIFEST.json's _comment and any other underscore-prefixed metadata
  if (key.charAt(0) === "_") return false;
  var entry = manifest[key];
  return entry && typeof entry === "object" && typeof entry.version === "string";
}).map(function (key) {
  var entry = manifest[key];
  var c = {
    "type":      "library",
    "bom-ref":   key + "@" + entry.version,
    "name":      key,
    "version":   entry.version,
    "purl":      _purlFor(entry, key),
    "scope":     "required",
  };
  if (entry.author)      c.author = entry.author;
  if (entry.description) c.description = entry.description;
  if (entry.license) {
    c.licenses = [{ license: { id: entry.license } }];
  }
  if (entry.source) {
    c.externalReferences = [{ type: "vcs", url: entry.source }];
  }
  var hashes = _hashesFor(entry);
  if (hashes.length > 0) c.hashes = hashes;
  if (entry.bundledAt) {
    c.properties = [{ name: "blamejs:bundledAt", value: entry.bundledAt }];
  }
  return c;
});

var doc = {
  "$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat":    "CycloneDX",
  "specVersion":  "1.6",
  "serialNumber": serialNumber,
  "version":      1,
  "metadata": {
    "timestamp": new Date().toISOString(),
    "lifecycles": [{ "phase": "build" }],
    "supplier":  FRAMEWORK_SUPPLIER,
    "tools": [
      {
        "vendor":  "blamejs",
        "name":    "build-vendored-sbom.js",
        "version": rootPkg.version,
      },
    ],
    "component": {
      "bom-ref":     "@blamejs/core@" + rootPkg.version + "/vendored-bundle",
      "type":        "library",
      "name":        "blamejs-vendored-bundle",
      "version":     rootPkg.version,
      "description": "Vendored runtime deps bundled inside @blamejs/core (CommonJS rollups under lib/vendor/).",
    },
  },
  "components":   components,
  "dependencies": [
    {
      "ref":       "@blamejs/core@" + rootPkg.version + "/vendored-bundle",
      "dependsOn": components.map(function (c) { return c["bom-ref"]; }),
    },
  ],
};

process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
