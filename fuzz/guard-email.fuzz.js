"use strict";

var b      = require("..");
var runner = require("./_runner");

var SEEDS = [
  "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nbody\r\n",
  "From: alice@example.com\nTo: bob@example.com\nSubject: hi\n\nbody\n",
  "From: alice@example.com\rTo: bob@example.com\r\n\r\nMAIL FROM:<x>\r\nDATA\r\n",
  "From: \"alice <evil@attacker>\" <alice@example.com>\r\nTo: bob@example.com\r\n\r\nbody\r\n",
  "From: alice@[1.2.3.4]\r\nTo: bob@example.com\r\n\r\n",
  "From: alice@xn--80akhbyknj4f.example\r\nTo: bob@example.com\r\n\r\n",
  "From: alice@‮example.com\r\nTo: bob@example.com\r\n\r\n",
  "From: " + "x".repeat(1000) + "@example.com\r\nTo: bob@example.com\r\n\r\n",
  "From: a@b\r\nSubject: " + "x".repeat(2000) + "\r\n\r\n",
];

runner.fuzz({
  name:   "b.guardEmail.validateMessage",
  target: function (input) { b.guardEmail.validateMessage(input, { profile: "strict" }); },
  generator: function () {
    var r = Math.random();
    if (r < 0.3) return runner.mutateSeed(runner.pick(SEEDS));
    if (r < 0.5) return runner.randomBidiSalt(runner.pick(SEEDS));
    if (r < 0.7) return runner.randomAscii(4096);
    return runner.randomUtf8(2048);
  },
});
