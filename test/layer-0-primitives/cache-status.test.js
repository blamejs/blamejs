"use strict";
/**
 * b.cacheStatus — RFC 9211 Cache-Status header builder + parser.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("cacheStatus.append is fn", typeof b.cacheStatus.append === "function");
  check("cacheStatus.entry is fn",  typeof b.cacheStatus.entry === "function");
  check("cacheStatus.parse is fn",  typeof b.cacheStatus.parse === "function");
  check("FWD_VALUES is array",      Array.isArray(b.cacheStatus.FWD_VALUES));
  check("CacheStatusError is a constructor",
        typeof b.cacheStatus.CacheStatusError === "function");
}

function testEntryFormats() {
  check("entry: cache name only", b.cacheStatus.entry({ cache: "x" }) === "x");
  check("entry: hit + ttl",
        b.cacheStatus.entry({ cache: "blamejs", hit: true, ttl: 600 })
        === "blamejs; hit; ttl=600");
  check("entry: full fwd shape",
        b.cacheStatus.entry({ cache: "cdn", hit: false, fwd: "miss", stored: true, ttl: 300 })
        === "cdn; stored; fwd=miss; ttl=300");
  check("entry: with detail (quoted)",
        b.cacheStatus.entry({ cache: "x", detail: "say \"hi\"" })
        .indexOf('detail="say \\"hi\\""') !== -1);
}

function testEntryRefusesBadShape() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("entry({}): bad cache",
             function () { b.cacheStatus.entry({}); }, "cache-status/bad-cache-name");
  expectCode("entry: bad fwd",
             function () { b.cacheStatus.entry({ cache: "x", fwd: "unknown" }); }, "cache-status/bad-fwd");
  expectCode("entry: bad fwd-status (low)",
             function () { b.cacheStatus.entry({ cache: "x", fwdStatus: 99 }); }, "cache-status/bad-fwd-status");
  expectCode("entry: bad ttl (negative)",
             function () { b.cacheStatus.entry({ cache: "x", ttl: -1 }); }, "cache-status/bad-ttl");
}

function testAppend() {
  var first = b.cacheStatus.append(null, { cache: "edge", hit: true, ttl: 60 });
  check("append: null prev gives single entry",
        first === "edge; hit; ttl=60");
  var second = b.cacheStatus.append(first, { cache: "origin", fwd: "miss" });
  check("append: chains entries",
        second === "edge; hit; ttl=60, origin; fwd=miss");
}

function testParseRoundTrip() {
  var rows = b.cacheStatus.parse('ExampleCDN; hit; ttl=300, blamejs; fwd=miss; stored; ttl=3600');
  check("parse: 2 entries",       rows.length === 2);
  check("parse[0].cache",         rows[0].cache === "ExampleCDN");
  check("parse[0].params.hit",    rows[0].params.hit === true);
  check("parse[0].params.ttl",    rows[0].params.ttl === 300);
  check("parse[1].cache",         rows[1].cache === "blamejs");
  check("parse[1].params.fwd",    rows[1].params.fwd === "miss");
  check("parse[1].params.stored", rows[1].params.stored === true);
}

function testParseQuotedStrings() {
  var rows = b.cacheStatus.parse('x; key="a;b,c"; detail="re,al"');
  check("parse: quoted commas/semis preserved",
        rows.length === 1 && rows[0].params.key === "a;b,c" && rows[0].params.detail === "re,al");
}

function testParseDefensive() {
  check("parse(null) → []",          Array.isArray(b.cacheStatus.parse(null)) && b.cacheStatus.parse(null).length === 0);
  check("parse('') → []",            b.cacheStatus.parse("").length === 0);
  check("parse(non-string) → []",    b.cacheStatus.parse({}).length === 0);
}

async function run() {
  testSurface();
  testEntryFormats();
  testEntryRefusesBadShape();
  testAppend();
  testParseRoundTrip();
  testParseQuotedStrings();
  testParseDefensive();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
