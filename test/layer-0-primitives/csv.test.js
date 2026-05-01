"use strict";
/**
 * b.csv — RFC 4180 parser + serializer.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // ---- Surface ----
  check("b.csv namespace present",        typeof b.csv === "object");
  check("b.csv.parse is fn",              typeof b.csv.parse === "function");
  check("b.csv.stringify is fn",          typeof b.csv.stringify === "function");
  check("b.csv.CsvError is class",        typeof b.csv.CsvError === "function");

  // ---- parse: header mode ----
  var p1 = b.csv.parse("a,b,c\n1,2,3\n4,5,6\n");
  check("parse: headers extracted",        p1.headers.join(",") === "a,b,c");
  check("parse: 2 rows",                   p1.rows.length === 2);
  check("parse: row 0 keyed correctly",    p1.rows[0].a === "1" && p1.rows[0].b === "2");

  // CRLF + LF + bare CR all work
  var p2 = b.csv.parse("a,b\r\n1,2\r\n3,4\r\n");
  check("parse: CRLF row terminators",     p2.rows.length === 2 && p2.rows[1].b === "4");
  var p3 = b.csv.parse("a,b\n1,2");
  check("parse: no trailing newline ok",   p3.rows.length === 1 && p3.rows[0].a === "1");

  // BOM stripped
  var p4 = b.csv.parse("﻿a,b\n1,2\n");
  check("parse: leading BOM consumed",     p4.headers[0] === "a");

  // Quoted fields with embedded comma + escaped quote + newline
  var quoted = "a,b\n\"hello, world\",\"he said \"\"hi\"\"\"\n\"line 1\nline 2\",x\n";
  var p5 = b.csv.parse(quoted);
  check("parse: quoted comma in field",     p5.rows[0].a === "hello, world");
  check("parse: escaped quote (\"\" → \")", p5.rows[0].b === 'he said "hi"');
  check("parse: embedded newline in quotes",p5.rows[1].a === "line 1\nline 2");

  // No-header mode
  var p6 = b.csv.parse("1,2,3\n4,5,6\n", { header: false });
  check("parse: no-header returns rows array",
        p6.rows.length === 2 && p6.rows[0][0] === "1" && p6.rows[1][2] === "6");

  // ---- parse: validation ----
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("parse-validate: " + label,  threw && codeRe.test(threw.code || ""));
  }
  rejects("non-string input",          function () { b.csv.parse(42); }, /csv\/bad-input/);
  rejects("multi-char delimiter",      function () { b.csv.parse("a,b\n1,2", { delimiter: ",," }); }, /csv\/bad-delimiter/);
  rejects("quote as delimiter",        function () { b.csv.parse("a,b\n1,2", { delimiter: '"' }); }, /csv\/bad-delimiter/);
  rejects("over maxBytes",             function () { b.csv.parse("a,b\n", { maxBytes: 1 }); }, /csv\/too-large/);
  rejects("bad onBadRow value",        function () { b.csv.parse("a,b\n1,2,3", { onBadRow: "panic" }); }, /csv\/bad-opt/);

  // Row-length mismatch — throw vs skip
  var threwRowMismatch = null;
  try { b.csv.parse("a,b,c\n1,2\n"); } catch (e) { threwRowMismatch = e; }
  check("parse: row-length mismatch throws by default",
        threwRowMismatch && /csv\/row-length-mismatch/.test(threwRowMismatch.code));
  var skipped = b.csv.parse("a,b,c\n1,2\n4,5,6\n", { onBadRow: "skip" });
  check("parse: onBadRow=skip drops bad row",
        skipped.rows.length === 1 && skipped.rows[0].a === "4");

  // Custom delimiter (semicolon)
  var p7 = b.csv.parse("a;b\n1;2\n", { delimiter: ";" });
  check("parse: custom delimiter",      p7.rows[0].b === "2");

  // ---- stringify ----
  var s1 = b.csv.stringify([{ a: "1", b: "2" }, { a: "3", b: "4" }]);
  check("stringify: emits header + rows",
        s1.indexOf("a,b\r\n1,2\r\n3,4\r\n") === 0);

  // Cells needing quoting
  var s2 = b.csv.stringify([{ a: 'hello, "world"', b: "ok" }]);
  check("stringify: quotes commas + escapes inner quotes",
        s2.indexOf('"hello, ""world""",ok') !== -1);

  // No-header
  var s3 = b.csv.stringify([{ a: "1", b: "2" }], { header: false });
  check("stringify: header=false skips header row",
        s3.indexOf("a,b") === -1 && s3.indexOf("1,2") === 0);

  // Explicit columns ordering
  var s4 = b.csv.stringify([{ a: "1", b: "2", c: "3" }], { columns: ["c", "a"] });
  check("stringify: explicit columns ordering",
        s4.indexOf("c,a\r\n3,1") === 0);

  // Array-of-arrays input
  var s5 = b.csv.stringify([["x", "y"], ["1", "2"]], { header: false });
  check("stringify: array-of-arrays",
        s5.indexOf("x,y\r\n1,2") === 0);

  // null / undefined → empty cell
  var s6 = b.csv.stringify([{ a: null, b: undefined, c: "v" }]);
  check("stringify: null/undef → empty",
        /a,b,c\r\n,,v/.test(s6));

  // Custom EOL
  var s7 = b.csv.stringify([{ a: "1" }], { eol: "\n" });
  check("stringify: custom EOL",        s7 === "a\n1\n");

  // ---- Round-trip ----
  var src = [
    { name: "Alice",     email: "a@example.com", note: 'said "hi"' },
    { name: "Bob, Jr.",  email: "b@example.com", note: "line1\nline2" },
  ];
  var written = b.csv.stringify(src);
  var read = b.csv.parse(written);
  check("round-trip: row count preserved",   read.rows.length === 2);
  check("round-trip: comma in name preserved",
        read.rows[1].name === "Bob, Jr.");
  check("round-trip: embedded quote preserved",
        read.rows[0].note === 'said "hi"');
  check("round-trip: embedded newline preserved",
        read.rows[1].note === "line1\nline2");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
