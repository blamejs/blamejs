"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "https://example.com/",
  "http://user:pass@example.com:8080/path?q=1#f",
  "ftp://example.com/file",
  "file:///etc/passwd",
  "javascript:alert(1)",
  "data:text/html,<script>alert(1)</script>",
  "https://exa‮mple.com/",
  "https://" + "a".repeat(2000) + ".example.com/",
  "https://1.2.3.4:80/",
  "https://[::1]/",
  "https://xn--80akhbyknj4f/",
  "https://google.com/../../etc/passwd",
];

runner.fuzz({
  name:   "b.safeUrl.parse",
  target: function (input) { b.safeUrl.parse(input); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(2048);
    return runner.randomUtf8(2048);
  },
});
