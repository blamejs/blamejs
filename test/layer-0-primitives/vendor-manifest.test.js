// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vendor-manifest.test.js
 *
 * Smoke-time gate that verifies every vendored file declared in
 * lib/vendor/MANIFEST.json matches the SHA-256 hash committed
 * alongside it. Closes the supply-chain class where a compromised
 * scripts/vendor-update.sh could swap a vendored dependency silently.
 *
 * The standalone gate at scripts/check-vendor-manifest.js exists too
 * (release-workflow + CI step); this duplicate sweep ensures
 * operators running `node test/smoke.js` locally catch hash drift
 * before commit, not at CI.
 */

var fs = require("fs");
var crypto = require("crypto");
var path = require("path");
var childProcess = require("child_process");
var check = require("../helpers/check").check;

var MANIFEST_PATH = "lib/vendor/MANIFEST.json";

function hashFile(p) {
  return "sha256:" + crypto.createHash("sha256")
    .update(fs.readFileSync(p)).digest("hex");
}

function hashTree(dir) {
  var entries = fs.readdirSync(dir, { withFileTypes: true })
    .sort(function (a, b) { return a.name.localeCompare(b.name); });
  var h = crypto.createHash("sha256");
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    var p = path.join(dir, e.name);
    h.update(e.name);
    if (e.isDirectory()) h.update(hashTree(p));
    else h.update(fs.readFileSync(p));
  }
  return "sha256-tree:" + h.digest("hex");
}

function computeHashes(pkgEntry) {
  if (!pkgEntry.files) return {};
  var out = {};
  var keys = Object.keys(pkgEntry.files);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    var fp = pkgEntry.files[k];
    if (typeof fp !== "string") continue;
    if (fp.endsWith("/")) {
      if (fs.existsSync(fp)) out[k] = hashTree(fp);
    } else if (fs.existsSync(fp)) {
      out[k] = hashFile(fp);
    } else {
      out[k] = "MISSING";
    }
  }
  return out;
}

function run() {
  var manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  var pkgs = Object.keys(manifest.packages);
  check("vendor manifest has at least one package",
        pkgs.length > 0);

  // NOTICE is the operator / compliance dependency inventory; each Component's
  // Version must match the vendored version. A re-vendor that bumped MANIFEST but
  // left NOTICE stale (five @blamejs/pki bumps did exactly that) reports a false
  // inventory — the same drift class as components[]/cpe below, on the
  // human-facing surface. vendor-update.sh now syncs it; this gates it.
  var noticeBlocks = fs.readFileSync("NOTICE", "utf8").split(Array(81).join("-"));

  var totalHashes = 0;
  for (var i = 0; i < pkgs.length; i += 1) {
    var name = pkgs[i];
    var pkg = manifest.packages[name];
    check("vendor manifest: " + name + " declares hashes",
          pkg.hashes && Object.keys(pkg.hashes).length > 0);
    var actual = computeHashes(pkg);
    var declared = pkg.hashes || {};
    var keys = Object.keys(actual);
    for (var k = 0; k < keys.length; k += 1) {
      var fk = keys[k];
      totalHashes += 1;
      check("vendor manifest: " + name + " :: " + fk + " hash matches",
            declared[fk] === actual[fk]);
    }

    // SBOM / CVE scanners (Trivy / Grype / a CycloneDX export) key on the
    // STRUCTURED components[<pkg>].version, not the human version string. A
    // hand-maintained components sub-object can drift from the version string
    // (#366: the bundle moved @peculiar/x509 1.13.0 -> 2.0.0, the version
    // string was updated to 2.0.0 but components still read 1.13.0, so any
    // advisory in the (1.13.0, 2.0.0] range matched the wrong version). Nothing
    // auto-derives components (refresh-vendor-manifest only refreshes hashes),
    // so gate the consistency here: every structured component version MUST
    // appear in the package's version string, making the drift un-shippable.
    if (pkg.components && typeof pkg.version === "string") {
      var compNames = Object.keys(pkg.components);
      var compVers = compNames
        .map(function (cn) { return pkg.components[cn] && pkg.components[cn].version; })
        .filter(function (v) { return typeof v === "string"; })
        .sort();
      var strVers = (pkg.version.match(/\d+\.\d+\.\d+/g) || []).slice().sort();

      // Every sub-component states its OWN upstream version, in semver, with
      // its own source. That is what removes the #366 drift: the version a
      // scanner reads has exactly one place to live, so it cannot fall behind
      // a version string that was bumped without it.
      check("vendor manifest: " + name + " :: every component declares a semver version " +
            "and a source url",
            compNames.every(function (cn) {
              var c = pkg.components[cn];
              return c && typeof c === "object" &&
                     typeof c.version === "string" && /^\d+\.\d+\.\d+/.test(c.version) &&
                     typeof c.url === "string" && c.url.length > 0;
            }));

      // A COMPOSITE version string ("2.0.0+pkijs-3.4.0") flattens several
      // packages into one entry, so it names the parent plus one token per
      // bundled package. There the tokens and the components must agree as a
      // MULTISET, not by substring: setting one component to another's version
      // passes an indexOf against the composite while the SBOM then reports
      // the wrong version for it, and {3.4.0,3.4.0} != {2.0.0,3.4.0} catches
      // exactly that. A plain version string names only the parent, whose
      // sub-components carry their own (legitimately different) versions —
      // two copies of @noble/hashes ship at different versions because each
      // bundle embeds the one it was built against — so there is nothing to
      // reconcile.
      if (strVers.length > 1) {
        check("vendor manifest: " + name + " :: composite version string tokens [" +
              strVers.join(",") + "] are exactly the components[] versions [" +
              compVers.join(",") + "]",
              compVers.length === strVers.length &&
              compVers.every(function (v, i) { return v === strVers[i]; }));
      }
    }

    // The cpe (Common Platform Enumeration) string encodes the version in
    // field 5 (cpe:2.3:a:vendor:product:VERSION:...) and CVE scanners match
    // against it — the same SBOM-drift class as components[] (#366 sibling:
    // @noble/curves shipped 2.2.0 but its cpe still read 0.0.0). Gate it: the
    // cpe version must equal the package's (leading) semver, so a wrong-version
    // CVE match can't ship.
    if (typeof pkg.cpe === "string") {
      var cpeM = /^cpe:2\.3:a:[^:]+:[^:]+:([^:]+):/.exec(pkg.cpe);
      var cpeVer = cpeM ? cpeM[1] : null;
      var pkgSemver = (String(pkg.version).match(/\d+\.\d+\.\d+/) || [null])[0];
      if (cpeVer !== null && cpeVer !== "*" && pkgSemver !== null) {
        check("vendor manifest: " + name + " :: cpe version (" + cpeVer +
              ") matches the package version (" + pkgSemver + ")",
              cpeVer === pkgSemver);
      }
    }

    // NOTICE Version parity (when this package has a NOTICE block).
    var noticeVer = null;
    for (var nbi = 0; nbi < noticeBlocks.length; nbi += 1) {
      var cm = noticeBlocks[nbi].match(/Component:\s+(\S+)/);
      if (cm && cm[1] === name) {
        var nvM = noticeBlocks[nbi].match(/Version:\s+(\S+)/);
        noticeVer = nvM ? nvM[1] : null;
        break;
      }
    }
    if (noticeVer !== null) {
      check("vendor manifest: " + name + " :: NOTICE version (" + noticeVer +
            ") matches the manifest version (" + pkg.version + ")",
            noticeVer === pkg.version);
    }
  }
  check("vendor manifest: scanned at least one hash",
        totalHashes > 0);

  // Declaring an embedded component only buys CVE coverage if the SBOM entry is
  // one a scanner can RESOLVE. `osv-scanner scan -L sbom.vendored.cdx.json`
  // matches on the purl's ecosystem, and pkg:generic names none to query — so an
  // embedded npm package emitted as pkg:generic is listed but silently
  // unscannable, which is worse than not declaring it at all because the
  // inventory then reads as covered. Namespacing a sub-component's NAME under
  // its parent (rather than only its bom-ref) did exactly that to all four
  // embedded @noble/* copies. Build the document and check what it actually
  // says, rather than trusting the generator's shape.
  var sbom = null;
  try {
    sbom = JSON.parse(childProcess.execFileSync(process.execPath,
      [path.join(__dirname, "..", "..", "scripts", "build-vendored-sbom.js")],
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }));
  } catch (e) {
    check("vendor sbom: builds and parses as JSON — " + (e && e.message), false);
  }

  if (sbom) {
    // Derive what the document MUST contain from the manifest, not from the
    // shape of what it happens to contain. Filtering the generated components
    // by name would let the very bug this guards against hide: a component
    // whose name was namespaced no longer looks like a package name, so a
    // name-shaped filter quietly drops it from the assertion.
    //
    // Data entries (the password list, the Public Suffix List, the BIMI
    // anchors) are not npm packages and carry snapshot markers rather than
    // versions, so they legitimately land on pkg:github / pkg:generic.
    var expectedNpmPurls = [];
    Object.keys(manifest.packages || {}).forEach(function (pkgName) {
      var entry = manifest.packages[pkgName];
      if (!/^@[a-z0-9-_.]+\/[a-z0-9-_.]+$/i.test(pkgName)) return;   // scoped npm names only
      expectedNpmPurls.push("pkg:npm/" +
        pkgName.replace(/^@/, "%40").replace("/", "%2F") + "@" + entry.version);
      var comps = entry.components;
      if (!comps || typeof comps !== "object") return;
      Object.keys(comps).forEach(function (subName) {
        var sub = comps[subName];
        var subVer = (sub && typeof sub === "object" && sub.version) || entry.version;
        expectedNpmPurls.push("pkg:npm/" +
          subName.replace(/^@/, "%40").replace("/", "%2F") + "@" + subVer);
      });
    });
    var actualPurls = (sbom.components || []).map(function (c) { return c.purl; });
    var missingPurls = expectedNpmPurls.filter(function (want) {
      return actualPurls.indexOf(want) === -1;
    });
    check("vendor sbom: the manifest declares at least one npm package to check " +
          "for (guards against this gate passing vacuously on an empty list)",
          expectedNpmPurls.length > 0);
    check("vendor sbom: every npm package the manifest declares — embedded ones " +
          "included — appears with a pkg:npm purl a scanner can resolve" +
          (missingPurls.length ? " (missing: " + missingPurls.join(", ") + ")" : ""),
          missingPurls.length === 0);
    // The bom-ref keeps the parent namespace, which is what lets two bundles
    // embedding the same package at different versions stay distinct entries
    // instead of collapsing into one.
    var refs = (sbom.components || []).map(function (c) { return c["bom-ref"]; });
    check("vendor sbom: every bom-ref is unique",
          refs.length === new Set(refs).size);
    var hashesCopies = (sbom.components || []).filter(function (c) {
      return c.name === "@noble/hashes";
    });
    check("vendor sbom: both embedded @noble/hashes copies are reported, each " +
          "at the version its own bundle was built against",
          hashesCopies.length === 2 &&
          hashesCopies[0].version !== hashesCopies[1].version);
  }

  // Operator-facing license-summary consistency. The README dependency-inventory
  // ends in a one-line summary that claims the tabulated set is "All ... MIT
  // licensed" with a named exception clause. A package the README TABULATES whose
  // NOTICE License is not MIT must be named — with its license — in that clause,
  // or the published inventory misstates a dependency's license. Adding a new
  // vendored bundle to the table (an Apache-2.0 @blamejs/pki) without amending the
  // summary published "all MIT" over an Apache-2.0 dependency. Scoped to
  // README-tabulated components (matched by their exact backtick token) so the
  // full NOTICE inventory — which lists deps the README highlight omits (MPL-2.0
  // publicsuffix-list, @noble/curves) — stays authoritative on its own surface.
  var readme    = fs.readFileSync("README.md", "utf8");
  var summaryM  = readme.match(/All are MIT licensed[^\n]*\./);
  check("README carries the vendor license-summary sentence", !!summaryM);
  var summary   = summaryM ? summaryM[0] : "";
  for (var lb = 0; lb < noticeBlocks.length; lb += 1) {
    var lcM = noticeBlocks[lb].match(/Component:\s+(.+)/);
    var llM = noticeBlocks[lb].match(/License:\s+(\S+)/);
    if (!lcM || !llM) continue;
    var comp = lcM[1].trim();
    var lic  = llM[1];
    if (/^MIT$/i.test(lic)) continue;                       // MIT is the summary's default claim
    if (readme.indexOf("`" + comp + "`") < 0) continue;     // not tabulated → NOTICE is authoritative
    check("README license summary names tabulated non-MIT dep " + comp + " (" + lic + ")",
          summary.indexOf(comp) >= 0 && summary.indexOf(lic) >= 0);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run();
  process.stdout.write("OK — vendor-manifest passed\n");
}
