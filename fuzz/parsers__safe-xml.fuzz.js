"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "<root><a>1</a><b>2</b></root>",
  '<?xml version="1.0" encoding="UTF-8"?><root/>',
  '<!DOCTYPE root [<!ENTITY x "y">]><root>&x;</root>',
  '<!DOCTYPE root SYSTEM "file:///etc/passwd"><root/>',
  "<root>" + "<a>".repeat(50) + "x" + "</a>".repeat(50) + "</root>",
  '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="x"/></root>',
  '<root attr="' + 'x'.repeat(2000) + '"/>',
  "<root>&#0;</root>",
  "<a>&" + "amp;".repeat(200) + "</a>",  // entity-expansion
];

runner.fuzz({
  name:   "b.parsers.xml.parse",
  target: function (input) { b.parsers.xml.parse(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
