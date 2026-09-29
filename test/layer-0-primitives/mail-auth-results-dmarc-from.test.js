// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `Authentication-Results` this framework writes reports the dmarc
 * method's `header.from` as the domain the IANA registry defines, not the
 * whole author address.
 *
 * The emitted header carried `header.from=someone@example.com`. The registry
 * entry for that property defines it as the domain of the `From` field, which
 * is also the only part DMARC evaluates: RFC 7489 §3.1 aligns on the From
 * domain and never on the local part.
 *
 * Measured in a consumer: a server read the property to decide which party an
 * aggregate report was about and called its address library's `parseDomain`
 * on it, which refused, correctly, because an address is not a domain. Every
 * report that arrived was recorded with an unreadable carrier domain and left
 * out of the reading a policy decision rested on. Nothing failed loudly: the
 * reports arrived, parsed, and were silently not counted.
 *
 * The local part is also not the receiver's to publish. `Authentication-
 * Results` travels with the message and is read by intermediaries and by the
 * recipient's client, so the address form puts the author's local part in
 * front of both for a property whose specified value is the domain alone.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

function _headerFor(entry) {
  return b.mail.authResults.emit({
    authservId: "mx.example.com",
    results:    [entry],
  });
}

function testTheDmarcPropertyIsADomain() {
  var header = _headerFor({ method: "dmarc", result: "pass", from: "example.com" });
  check("a domain is emitted under header.from",
        /header\.from=example\.com/.test(header), header);
  check("and no address reaches the header",
        header.indexOf("@") === -1, header);
}

function testTheEmitterRefusesAnAddressUnderTheDomainProperty() {
  // The registered property is a domain. Handing it an address is the caller
  // making the same mistake one layer up, so it is refused by name rather
  // than passed through to every reader of the message.
  var threw = null;
  try { _headerFor({ method: "dmarc", result: "pass", from: "someone@example.com" }); }
  catch (e) { threw = e; }
  check("an address under header.from is refused",
        threw !== null && /header\.from/.test((threw && threw.message) || ""),
        threw && (threw.code + " " + threw.message));
}

async function testTheVerifiedHeaderCarriesTheDomain() {
  // The consumer path: what b.mail.inbound.verify writes after evaluating a
  // message whose From carries a local part.
  var message = [
    "From: Someone <someone@example.com>",
    "To: victim@example.net",
    "Subject: hi",
    "",
    "body",
    "",
  ].join("\r\n");
  var rv = await b.mail.inbound.verify({
    message:    Buffer.from(message, "utf8"),
    ip:         "192.0.2.1",
    helo:       "mail.example.com",
    mailFrom:   "someone@example.com",
    authservId: "mx.example.com",
    dnsLookup:  function () { return Promise.resolve([]); },
  });
  var header = rv && rv.authResults;
  check("the written header reports a dmarc verdict", typeof header === "string" &&
        header.indexOf("dmarc=") !== -1, String(header));
  check("its header.from is the domain, with no local part",
        /header\.from=example\.com/.test(String(header)) &&
        !/header\.from=[^;\s]*@/.test(String(header)), String(header));
  // The envelope property keeps its address: RFC 8601 §2.7.1 defines
  // smtp.mailfrom as the MAIL FROM value, which is an address.
  check("smtp.mailfrom still carries the envelope address",
        /smtp\.mailfrom=someone@example\.com/.test(String(header)), String(header));
}

async function run() {
  testTheDmarcPropertyIsADomain();
  testTheEmitterRefusesAnAddressUnderTheDomainProperty();
  await testTheVerifiedHeaderCarriesTheDomain();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-auth-results-dmarc-from] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
