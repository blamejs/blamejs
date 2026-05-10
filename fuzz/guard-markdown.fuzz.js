"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "# Heading\n\nParagraph **bold** _italic_.",
  "[link](javascript:alert(1))",
  "[link](&#x6A;avascript:alert(1))",
  "![img](javascript:alert(1))",
  "<script>alert(1)</script>",
  "<script\n>alert(1)</script>",
  "[ref]: javascript:alert(1)\n[link][ref]",
  "---\nfront: matter\n---\n# Body",
  "<!--\nhtml comment\n-->\n",
  "**" + "very ".repeat(200) + "long emphasis**",
  "```evil<>'\"\n```",
  "* a\n  * b\n    * c\n      * d\n        * e\n",
];

runner.fuzz({
  name:   "b.guardMarkdown.validate",
  target: function (input) { b.guardMarkdown.validate(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
