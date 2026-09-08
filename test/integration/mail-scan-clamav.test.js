// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live ClamAV INSTREAM round-trip against the docker-compose clamd fixture.
 *
 * Exercises lib/mail-scan.js's `clamav-instream` transport against a real
 * daemon: the `zINSTREAM\0` command, the 4-byte-length-prefixed chunk
 * framing, the zero-length terminator, and the reply parser. The unit suite
 * drives the same code through an injected `_socket`, which proves the parser
 * against replies the test wrote itself; it cannot show that the bytes on the
 * wire are the ones clamd expects.
 *
 * The fixture sets StreamMaxLength to 1M rather than the 25M default, so the
 * size-limit reply is reachable without sending 25 MB.
 */
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b        = require("../../");

// The EICAR test string. ClamAV detects it by whole-file signature, so it is
// sent as the entire message: the same 68 bytes inside a larger body do not
// match, which is a property of the signature rather than of the transport.
var EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

// docker/clamav/clamd.conf. clamd accepts a stream up to and including this
// many bytes and refuses the next one.
var STREAM_MAX = 1048576;

// The endpoint the service helper probed, so a BLAMEJS_CLAMAV_URL override
// reaches the scan and not just the reachability check.
function _handle(svc) {
  return b.mail.scan.create({
    protocol: "clamav-instream", host: svc.host, port: svc.port,
  });
}

async function run() {
  var svc = await services.requireService("clamav");
  if (!svc.ok) throw new Error("clamav unreachable: " + svc.reason);

  var h = _handle(svc);

  // ---- a clean message scans clean ----
  var clean = await h.scan(Buffer.from("Subject: hello\r\n\r\nplain body\r\n"));
  check("clean: verdict is clean", clean.verdict === "clean", JSON.stringify(clean));
  check("clean: no threats named", Array.isArray(clean.threats) && clean.threats.length === 0);

  // ---- a known signature is reported with its name ----
  var eicar = await h.scan(Buffer.from(EICAR, "binary"));
  check("eicar: verdict is infected", eicar.verdict === "infected", JSON.stringify(eicar));
  check("eicar: the daemon's threat name survives the reply parser",
        eicar.threats.length === 1 && /eicar/i.test(eicar.threats[0]),
        JSON.stringify(eicar.threats));

  // ---- chunk framing is byte-accurate ----
  //
  // The transport writes 64 KiB chunks, each behind a 4-byte big-endian
  // length, then a zero-length terminator. clamd counts the bytes it is given
  // and refuses the stream once the count passes StreamMaxLength, so the
  // accept/refuse boundary is a byte-exact readout of what the framing
  // actually delivered across sixteen chunks. A wrong length prefix, a chunk
  // written out of order, or a terminator sent early moves the boundary.
  var atCap = await h.scan(Buffer.alloc(STREAM_MAX, 0x41));
  check("framing: a stream of exactly StreamMaxLength is accepted",
        atCap.verdict === "clean", STREAM_MAX + " -> " + JSON.stringify(atCap));

  var overCap = await h.scan(Buffer.alloc(STREAM_MAX + 1, 0x41));
  check("framing: one byte more is refused",
        overCap.verdict === "error", (STREAM_MAX + 1) + " -> " + JSON.stringify(overCap));

  // A refusal on size and a daemon fault are both `verdict: "error"`, and the
  // first will never succeed on retry while the second clears on its own.
  check("size limit: the refusal names itself rather than reading as a fault",
        overCap.errorCode === "mail-scan/clamav-size-limit", JSON.stringify(overCap));
  check("size limit: the daemon's own words come back with it",
        typeof overCap.errorMessage === "string" &&
        /size limit exceeded/i.test(overCap.errorMessage), JSON.stringify(overCap.errorMessage));

  // ---- the size-limit reply is a verdict, not a transport failure ----
  //
  // clamd closes the connection as soon as the cap is passed, while the
  // transport is still writing the remaining chunks, so the reply and the
  // write error race. The reply has to win every time: a write error would
  // reach the caller as a scanner outage rather than a message too large.
  //
  // Keyed on the error CODE, not on the verdict. A transport rejection is
  // caught and resolved as `verdict: "error"` too, so counting verdicts
  // passes when all six fail at the socket, which is the outcome this is
  // meant to rule out.
  var outcomes = Object.create(null);
  for (var i = 0; i < 6; i += 1) {
    var key;
    try {
      var attempt = await h.scan(Buffer.alloc(4 * 1024 * 1024, 0x41));
      key = attempt.verdict + ":" + (attempt.errorCode || "none");
    } catch (e) { key = "threw:" + (e.code || e.message); }
    outcomes[key] = (outcomes[key] || 0) + 1;
  }
  check("size limit: the daemon's reply wins the race every time",
        outcomes["error:mail-scan/clamav-size-limit"] === 6, JSON.stringify(outcomes));

  // ---- the framework's own cap refuses before any socket work ----
  var tooBig = null;
  try { await h.scan(Buffer.alloc(b.mail.scan.PROFILES.strict.maxMessageBytes + 1, 0x41)); }
  catch (e) { tooBig = e; }
  check("message cap: past maxMessageBytes throws mail-scan/oversize-message",
        tooBig !== null && tooBig.code === "mail-scan/oversize-message",
        String(tooBig && tooBig.code));

  // ---- the IPv6 mapping serves the same daemon ----
  var v6 = await services.requireService("clamavV6");
  if (v6.ok) {
    var cleanV6 = await _handle(v6).scan(Buffer.from("Subject: v6\r\n\r\nbody\r\n"));
    check("ipv6: the [::1] mapping scans clean",
          cleanV6.verdict === "clean", JSON.stringify(cleanV6));
  } else {
    check("ipv6: the [::1] mapping is reachable", false, v6.reason);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
