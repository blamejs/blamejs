// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A JMAP submission is authorized against its identity the way the SMTP
 * submission server authorizes the same account.
 *
 * The handler compared `envelope.mailFrom.email` with the identity's
 * `email` as raw strings, so it refused `ops@EXAMPLE.com` for
 * `ops@example.com` though RFC 5321 section 2.4 makes a domain
 * case-insensitive, refused the A-label form of an internationalized
 * domain though RFC 5890 section 2.3.2.4 makes the two equivalent, refused
 * every sender for the `*@example.com` identity RFC 8621 section 6 defines
 * as covering a whole domain, and let a submission through unchecked when
 * the identity carried no address at all. It never read the message's From
 * header, so an authorized envelope could carry a message claiming to be
 * from anyone.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var IDENTITIES = [
  { id: "I1", email: "ops@example.com" },
  { id: "I2", email: "*@example.com" },
  { id: "I3", email: "ops@bücher.example" },
  { id: "I4" },
  // RFC 5322 section 3.4.1 quoted local part.
  { id: "I5", email: "\"ops\"@example.com" },
];

function _message(fromHeader) {
  return Buffer.from(
    "From: " + fromHeader + "\r\n" +
    "To: dest@example.net\r\n" +
    "Subject: probe\r\n" +
    "\r\n" +
    "body\r\n", "utf8");
}

async function _submit(opts) {
  var delivered = [];
  var handler = b.mail.server.jmap.emailSubmissionSetHandler({
    identities:  function () { return IDENTITIES; },
    // Unless a row is about the From header, the message claims to be from
    // the same address the envelope does.
    lookupEmail: async function () { return _message(opts.fromHeader || opts.mailFrom); },
    deliver:     async function (envelope) {
      delivered.push(envelope);
      return { delivered: [{ recipient: "dest@example.net", smtpReply: "250 Accepted" }] };
    },
    subaddressDelimiter: opts.subaddressDelimiter,
  });
  var rv = await handler({ id: "actor1" }, {
    accountId: "A1",
    create: {
      s0: {
        identityId: opts.identityId,
        emailId:    "e1",
        envelope:   {
          mailFrom: { email: opts.mailFrom },
          rcptTo:   [{ email: "dest@example.net" }],
        },
      },
    },
  });
  var notCreated = rv.notCreated && rv.notCreated.s0;
  return {
    created:    rv.created && rv.created.s0 ? true : false,
    error:      notCreated ? (notCreated.type || notCreated.code) : null,
    deliveredFrom: delivered.length ? delivered[0].from : null,
  };
}

async function testTheIdentityMatchIsNormalizedLikeSmtp() {
  var ROWS = [
    { label: "the identity's own address",
      identityId: "I1", mailFrom: "ops@example.com", want: "created" },
    { label: "an upper-case domain",
      identityId: "I1", mailFrom: "ops@EXAMPLE.com", want: "created" },
    { label: "a mixed-case domain",
      identityId: "I1", mailFrom: "ops@Example.Com", want: "created" },
    { label: "a subaddress with no delimiter configured",
      identityId: "I1", mailFrom: "ops+news@example.com", want: "forbiddenMailFrom" },
    { label: "a subaddress with the delimiter configured",
      identityId: "I1", mailFrom: "ops+news@example.com", subaddressDelimiter: "+", want: "created" },
    { label: "any address at a wildcard identity's domain",
      identityId: "I2", mailFrom: "sales@example.com", want: "created" },
    { label: "an address outside a wildcard identity's domain",
      identityId: "I2", mailFrom: "sales@other.example", want: "forbiddenMailFrom" },
    { label: "the A-label form of an internationalized domain",
      identityId: "I3", mailFrom: "ops@xn--bcher-kva.example", want: "created" },
    { label: "an identity carrying no address",
      identityId: "I4", mailFrom: "ceo@bank.example", want: "forbiddenMailFrom" },
    { label: "a different mailbox at the identity's domain",
      identityId: "I1", mailFrom: "ceo@example.com", want: "forbiddenMailFrom" },
    // RFC 5321 section 2.4 makes the domain case-insensitive and leaves the
    // local part to the receiving host, so only the domain is folded. Folding
    // the local part as well would let `OPS@example.com` pass as the identity
    // on a host that treats it as a different mailbox.
    { label: "the identity's local part in another case",
      identityId: "I1", mailFrom: "OPS@example.com", want: "forbiddenMailFrom" },
  ];

  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var row = ROWS[i];
    var got = await _submit(row);
    var answer = got.created ? "created" : got.error;
    if (answer !== row.want) wrong.push(row.label + " -> " + answer);
  }
  check("a submission is authorized against its identity the way SMTP authorizes it" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testAQuotedDisplayNameDoesNotHijackTheAddress() {
  // RFC 5322 section 3.4 lets a display name be a quoted-string, and a
  // quoted-string may hold `<` and `>`. Taking the first angle bracket in the
  // field reads the display name's text as the address, so an authorized
  // submission was refused with forbiddenFrom. A comment may carry them too
  // (section 3.2.2).
  var ROWS = [
    { label: "plain address",            from: "ops@example.com" },
    { label: "display name and angles",  from: "Ops <ops@example.com>" },
    { label: "quoted display name holding angles",
      from: '"Sales <US>" <ops@example.com>' },
    { label: "quoted display name holding an at-sign",
      from: '"ceo@bank.example" <ops@example.com>' },
    { label: "comment before the address",
      from: "(the sales desk) ops@example.com" },
    { label: "escaped quote inside the display name",
      from: '"Ops \\" <nobody@evil.example>" <ops@example.com>' },
  ];
  var wrong = [];
  for (var i = 0; i < ROWS.length; i += 1) {
    var got = await _submit({ identityId: "I1", mailFrom: "ops@example.com",
                              fromHeader: ROWS[i].from });
    if (!got.created) wrong.push(ROWS[i].label + " -> " + got.error);
  }
  check("the address is read past a quoted display name or comment" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);

  // The check still bites: a genuinely foreign From is still refused.
  var foreign = await _submit({ identityId: "I1", mailFrom: "ops@example.com",
                                fromHeader: '"Ops" <ceo@bank.example>' });
  check("a From the identity does not cover is still forbiddenFrom",
        foreign.error === "forbiddenFrom", JSON.stringify(foreign));

  // RFC 5322 section 3.4.1 lets the LOCAL PART be a quoted-string, and a
  // quoted run followed by `@` is an address rather than a display name.
  // Skipping it as though it were a name leaves `@example.com`, which covers
  // no identity, so an authorized submission is refused.
  var quotedLocal = await _submit({
    identityId: "I5", mailFrom: '"ops"@example.com',
    fromHeader: '"ops"@example.com',
  });
  check("a bare address whose local part is quoted keeps its local part",
        quotedLocal.created === true, JSON.stringify(quotedLocal));
  var quotedLocalInAngles = await _submit({
    identityId: "I5", mailFrom: '"ops"@example.com',
    fromHeader: 'Ops Desk <"ops"@example.com>',
  });
  check("and the same address inside angle brackets is read the same way",
        quotedLocalInAngles.created === true, JSON.stringify(quotedLocalInAngles));
}

async function testTheFromHeaderIsCheckedToo() {
  var authorizedEnvelope = await _submit({
    identityId: "I1", mailFrom: "ops@example.com", fromHeader: "ceo@bank.example",
  });
  check("a message whose From header the identity does not cover is forbiddenFrom",
        authorizedEnvelope.created === false && authorizedEnvelope.error === "forbiddenFrom",
        JSON.stringify(authorizedEnvelope));
  check("nothing was delivered for it", authorizedEnvelope.deliveredFrom === null);

  var matching = await _submit({
    identityId: "I1", mailFrom: "ops@example.com", fromHeader: "Ops <ops@EXAMPLE.com>",
  });
  check("a From header that differs only in case is accepted",
        matching.created === true && matching.deliveredFrom === "ops@example.com",
        JSON.stringify(matching));
}

async function run() {
  await testTheIdentityMatchIsNormalizedLikeSmtp();
  await testAQuotedDisplayNameDoesNotHijackTheAddress();
  await testTheFromHeaderIsCheckedToo();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-submission-sender] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
