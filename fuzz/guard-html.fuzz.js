"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "<p>hello</p>",
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<a href=\"javascript:alert(1)\">x</a>",
  "<a href=\"&#x6A;avascript:alert(1)\">x</a>",
  "<svg/onload=alert(1)>",
  "<style>@import 'x';</style>",
  "<form id=foo><input name=submit></form>",
  "<!--[if IE]><script>alert(1)</script><![endif]-->",
  "<div " + "data-".repeat(100) + "x=y>",
];

runner.fuzz({
  name:   "b.guardHtml.validate",
  target: function (input) { b.guardHtml.validate(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
