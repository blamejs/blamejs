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
  // A quoted local part may hold the angle brackets that delimit the address.
  { id: "I6", email: "\"a>b\"@example.com" },
  // RFC 5322 section 3.4.1 lets a local part be quoted, so this is the literal
  // mailbox named `*`, not the wildcard RFC 8621 section 6 defines.
  { id: "I7", email: "\"*\"@example.com" },
  // RFC 5321 section 4.1.3 and RFC 5322 section 3.4.1 make a bracketed address
  // literal a legal domain.
  { id: "I8", email: "ops@[192.0.2.1]" },
  { id: "I9", email: "ops@[IPv6:2001:db8::1]" },
  // RFC 6531 section 3.3 extends atext with UTF8-non-ascii, so an SMTPUTF8
  // deployment's identity can carry one in the local part.
  { id: "I10", email: "üser@example.com" },
];

// `rawHeaders` writes the header block verbatim, for a row whose point is
// where a header sits relative to another. The default prefixes `From: `,
// which puts a real From first and hides anything a later row wanted to test.
function _message(fromHeader, rawHeaders) {
  var head = rawHeaders !== undefined && rawHeaders !== null
    ? rawHeaders
    : "From: " + fromHeader + "\r\n";
  return Buffer.from(
    head +
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
    lookupEmail: async function () {
      return _message(opts.fromHeader || opts.mailFrom, opts.rawHeaders);
    },
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
    // RFC 8621 section 6 spells the domain-wide identity `*@domain`. RFC 5322
    // section 3.4.1 lets a local part be a quoted string, so `"*"@domain` is
    // the mailbox named `*` and covers itself alone. Unquoting the identity
    // before the wildcard test read one as the other, and the operator writes
    // the identity list.
    { label: "a quoted asterisk is a mailbox, not a wildcard",
      identityId: "I7", mailFrom: "victim@example.com", want: "forbiddenMailFrom" },
    { label: "and that mailbox still covers itself",
      identityId: "I7", mailFrom: "\"*\"@example.com", want: "created" },
    { label: "while the unquoted wildcard still covers its domain",
      identityId: "I2", mailFrom: "anyone@example.com", want: "created" },
    // The domain of an address literal is the bracketed text itself. Handing
    // it to the A-label conversion, which declines it, made an identity fail
    // to cover the address it IS: the same string, byte for byte, refused.
    { label: "an address literal covers itself",
      identityId: "I8", mailFrom: "ops@[192.0.2.1]", want: "created" },
    { label: "and so does an IPv6 literal",
      identityId: "I9", mailFrom: "ops@[IPv6:2001:db8::1]", want: "created" },
    { label: "a different literal is a different domain",
      identityId: "I8", mailFrom: "ops@[192.0.2.2]", want: "forbiddenMailFrom" },
    { label: "and a named domain is not the literal that resolves to it",
      identityId: "I8", mailFrom: "ops@example.com", want: "forbiddenMailFrom" },
    { label: "a different mailbox at the same literal is still refused",
      identityId: "I8", mailFrom: "ceo@[192.0.2.1]", want: "forbiddenMailFrom" },
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

  // The quoted local part may itself hold the bracket that ends the address,
  // so the closing one is the first that is not inside a quoted string.
  // Taking the first `>` in the field cut the address at it and refused an
  // authorized submission.
  var bracketInLocal = await _submit({
    identityId: "I6", mailFrom: '"a>b"@example.com',
    fromHeader: 'Example <"a>b"@example.com>',
  });
  check("a quoted local part holding an angle bracket is read whole",
        bracketInLocal.created === true, JSON.stringify(bracketInLocal));
  // RFC 5322 3.2.2 allows a comment wherever folding whitespace may appear,
  // which includes inside the angle brackets and between the atoms of the
  // address. Only the outer ones were removed, so the comment was compared as
  // part of the mailbox and an authorized submission was refused.
  var commentRows = [
    "Ops <ops@example.com (work)>",
    "Ops <(work) ops@example.com>",
    "Ops <ops(work)@example.com>",
    "Ops <ops@(mail host)example.com>",
    "ops@example.com (work)",
  ];
  var refusedWithComment = [];
  for (var c = 0; c < commentRows.length; c += 1) {
    var withComment = await _submit({ identityId: "I1", mailFrom: "ops@example.com",
                                      fromHeader: commentRows[c] });
    if (!withComment.created) refusedWithComment.push(commentRows[c] + " -> " + withComment.error);
  }
  check("a comment anywhere in the address is not part of the mailbox" +
        (refusedWithComment.length ? " (" + refusedWithComment.join("; ") + ")" : ""),
        refusedWithComment.length === 0);

  // A comment is not a licence to read a different mailbox.
  var foreignWithComment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Ops <ceo@bank.example (ops@example.com)>",
  });
  check("and a comment naming the identity does not authorize a foreign address",
        foreignWithComment.error === "forbiddenFrom", JSON.stringify(foreignWithComment));

  var unterminated = await _submit({
    identityId: "I6", mailFrom: '"a>b"@example.com',
    fromHeader: 'Example <"a>b"@example.com',
  });
  check("while an address with no closing bracket names no mailbox",
        unterminated.created !== true, JSON.stringify(unterminated));
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

async function testEveryMailboxOfAFromListIsChecked() {
  // RFC 5322 section 3.6.2 lets From carry a mailbox-list, and every mailbox
  // in it is an author the message claims. The reader stopped at the first
  // comma, so an authorized address in front covered any address behind it
  // and the message went out claiming both.
  var twoAuthors = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, ceo@bank.example",
  });
  check("a second author the identity does not cover is forbiddenFrom",
        twoAuthors.created === false && twoAuthors.error === "forbiddenFrom",
        JSON.stringify(twoAuthors));
  check("nothing was delivered for it", twoAuthors.deliveredFrom === null);

  // A list every mailbox of which the identity covers still goes out.
  var bothCovered = await _submit({
    identityId: "I2", mailFrom: "sales@example.com",
    fromHeader: "sales@example.com, support@example.com",
  });
  check("a list the identity covers entirely is accepted",
        bothCovered.created === true, JSON.stringify(bothCovered));

  // A comma inside a quoted display name does not start a new mailbox.
  var quotedComma = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: '"Operations, Team" <ops@example.com>',
  });
  check("a comma inside a quoted display name is not a list separator",
        quotedComma.created === true, JSON.stringify(quotedComma));

  // The splitter models quoted strings; the field also carries COMMENTS, and
  // RFC 5322 3.2.2 ctext runs %d33-39 / %d42-91 / %d93-126, which includes
  // DQUOTE. So `(")` is a legal comment, and reading that `"` as opening a
  // quoted string swallowed the rest of the field: the splitter returned one
  // chunk, the reader took its first mailbox, and every later author went
  // unchecked. The sender writes the comment.
  var hiddenByComment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: 'ops@example.com ("), ceo@bank.example',
  });
  check("a DQUOTE inside a comment does not hide a later author",
        hiddenByComment.created === false && hiddenByComment.error === "forbiddenFrom",
        JSON.stringify(hiddenByComment));

  // RFC 6854 section 2.1 lets From carry an address-list, and RFC 5322
  // section 3.4 defines an address as a mailbox OR a group,
  // `display-name ":" [group-list] ";"`. A group's members are the authors;
  // reading the whole construct as one address refused a message whose only
  // author is the identity's own.
  var groupOfOne = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Authors: ops@example.com;",
  });
  check("a group naming only the identity's own address is accepted",
        groupOfOne.created === true, JSON.stringify(groupOfOne));

  // A group's mailbox-list is comma separated, so its members have to survive
  // the same split the top level uses, and each is checked in its own right.
  var groupOfTwoCovered = await _submit({
    identityId: "I2", mailFrom: "sales@example.com",
    fromHeader: "Team: sales@example.com, support@example.com;",
  });
  check("a group the identity covers entirely is accepted",
        groupOfTwoCovered.created === true, JSON.stringify(groupOfTwoCovered));

  var groupHidingAnAuthor = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Authors: ops@example.com, ceo@bank.example;",
  });
  check("an author inside a group is checked like any other",
        groupHidingAnAuthor.created === false &&
        groupHidingAnAuthor.error === "forbiddenFrom",
        JSON.stringify(groupHidingAnAuthor));
  check("nothing was delivered for the group hiding an author",
        groupHidingAnAuthor.deliveredFrom === null);

  var groupBesideAMailbox = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, Authors: ceo@bank.example;",
  });
  check("a group following a mailbox does not hide its members",
        groupBesideAMailbox.created === false &&
        groupBesideAMailbox.error === "forbiddenFrom",
        JSON.stringify(groupBesideAMailbox));

  var groupAfterAMailbox = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Authors: ceo@bank.example;, ops@example.com",
  });
  check("a mailbox after a closed group does not cover the group's members",
        groupAfterAMailbox.created === false &&
        groupAfterAMailbox.error === "forbiddenFrom",
        JSON.stringify(groupAfterAMailbox));

  // RFC 5322 section 3.4 allows an empty group-list, which names no author at
  // all. Nothing to authorize is not the same as authorized.
  var emptyGroup = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Undisclosed recipients:;",
  });
  check("a group naming no author is refused",
        emptyGroup.created === false && emptyGroup.error === "forbiddenFrom",
        JSON.stringify(emptyGroup));

  // A group a sender never closes is not a group the reader can account for.
  var unterminatedGroup = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Authors: ops@example.com, ceo@bank.example",
  });
  check("an unterminated group is refused",
        unterminatedGroup.created === false &&
        unterminatedGroup.error === "forbiddenFrom",
        JSON.stringify(unterminatedGroup));

  // RFC 5322 section 2.2 makes a field name one or more ftext, the printable
  // ASCII except the colon, followed immediately by the colon. `From :` is
  // not a field name, so a receiving parser reads that line as no field at
  // all. This parser trimmed the text before the colon and authorized on it,
  // which approves a message whose From a conformant reader does not see.
  var spacedName = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From : ops@example.com\r\n",
  });
  check("a From whose field name carries a space is not read as a From",
        spacedName.created === false && spacedName.error === "forbiddenFrom",
        JSON.stringify(spacedName));
  check("nothing was delivered for it", spacedName.deliveredFrom === null);

  // The one beside it: the name written as the grammar requires still reads.
  var tightName = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\n",
  });
  check("the same header with no space before the colon is read",
        tightName.created === true, JSON.stringify(tightName));

  check("b.safeMime.isHeaderFieldName reads the grammar",
        b.safeMime.isHeaderFieldName("From") === true &&
        b.safeMime.isHeaderFieldName("From ") === false &&
        b.safeMime.isHeaderFieldName("Fr:om") === false &&
        b.safeMime.isHeaderFieldName("") === false &&
        b.safeMime.isHeaderFieldName("X-Odd!#$%") === true &&
        b.safeMime.isHeaderFieldName(null) === false);

  // A wildcard identity authorizes by domain, and the domain is read by
  // splitting at the last `@`. Nothing checked that what sits in front of it
  // is a local part, so `ceo@bank.example;ops@example.com` presented a local
  // part of `ceo@bank.example;ops` at `example.com` and the wildcard covered
  // the whole string. RFC 5322 section 3.2.3 makes an unquoted local part a
  // dot-atom, and `@` and `;` are not atext, so a receiving parser reads a
  // different author out of the same bytes than this check authorized.
  var spliceInFrom = await _submit({
    identityId: "I2", mailFrom: "sales@example.com",
    fromHeader: "ceo@bank.example;ops@example.com",
  });
  check("a From local part that is not a dot-atom is not covered by a wildcard",
        spliceInFrom.created === false && spliceInFrom.error === "forbiddenFrom",
        JSON.stringify(spliceInFrom));
  check("nothing was delivered for the spliced From", spliceInFrom.deliveredFrom === null);

  var spliceInEnvelope = await _submit({
    identityId: "I2", mailFrom: "ceo@bank.example;ops@example.com",
  });
  check("an envelope local part that is not a dot-atom is not covered either",
        spliceInEnvelope.created === false &&
        spliceInEnvelope.error === "forbiddenMailFrom",
        JSON.stringify(spliceInEnvelope));

  // The shapes either side of the boundary: a dot-atom with the punctuation
  // RFC 5322 section 3.2.3 admits still passes, and a doubled or edge dot does
  // not, because dot-atom joins atoms with single dots.
  var oddButLegal = await _submit({
    identityId: "I2", mailFrom: "a!#$%&'*+-/=?^_`{|}~b@example.com",
  });
  check("a local part using every atext punctuation is covered",
        oddButLegal.created === true, JSON.stringify(oddButLegal));

  // The dot-atom rule is RFC 5322's, which is ASCII. RFC 6531 section 3.3
  // adds UTF8-non-ascii to atext, and an identity whose local part carries
  // one has to still cover itself: reading the ASCII grammar over every
  // address refused an exact match.
  var eaiExact = await _submit({
    identityId: "I10", mailFrom: "üser@example.com",
  });
  check("an internationalized local part covers itself",
        eaiExact.created === true, JSON.stringify(eaiExact));

  var eaiOther = await _submit({
    identityId: "I10", mailFrom: "öther@example.com",
  });
  check("and a different internationalized local part does not",
        eaiOther.created === false && eaiOther.error === "forbiddenMailFrom",
        JSON.stringify(eaiOther));

  var eaiSpliced = await _submit({
    identityId: "I10", mailFrom: "üser@evil.example;x@example.com",
  });
  check("an internationalized local part is still held to the atom shape",
        eaiSpliced.created === false && eaiSpliced.error === "forbiddenMailFrom",
        JSON.stringify(eaiSpliced));

  // The subaddress suffix is dropped for the comparison, so it must be
  // dropped AFTER the address has been read as a mailbox: folding first made
  // the extra `@` of `ops+foo@evil.example@example.com` disappear before
  // anything looked at the local part.
  var splicedSubaddress = await _submit({
    identityId: "I1", mailFrom: "ops+foo@evil.example@example.com",
    subaddressDelimiter: "+",
  });
  check("a subaddress does not fold away a second at sign",
        splicedSubaddress.created === false &&
        splicedSubaddress.error === "forbiddenMailFrom",
        JSON.stringify(splicedSubaddress));
  check("nothing was delivered for the spliced subaddress",
        splicedSubaddress.deliveredFrom === null);

  // The border it sits next to: a subaddress on a well-formed address still
  // folds to the identity it belongs to.
  var plainSubaddress = await _submit({
    identityId: "I1", mailFrom: "ops+news@example.com", subaddressDelimiter: "+",
  });
  check("a subaddress on a well-formed address still folds",
        plainSubaddress.created === true, JSON.stringify(plainSubaddress));

  var badDots = ["a..b@example.com", ".ab@example.com", "ab.@example.com", "a b@example.com"];
  for (var bd = 0; bd < badDots.length; bd += 1) {
    var refused = await _submit({ identityId: "I2", mailFrom: badDots[bd] });
    check("a local part that is not a dot-atom is refused: " + badDots[bd],
          refused.created === false && refused.error === "forbiddenMailFrom",
          JSON.stringify(refused));
  }

  // A group's display-name is a phrase (RFC 5322 section 3.4), so everything
  // before the colon has to read as one. Discarding it unchecked let a mailbox
  // ride in front of the colon: the group's own member is the identity's
  // address, so the element passed, and the message went out naming an author
  // nobody authorized.
  var mailboxBeforeTheColon = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "<ceo@bank.example> Authors: ops@example.com;",
  });
  check("a mailbox in front of a group's colon is not discarded",
        mailboxBeforeTheColon.created === false &&
        mailboxBeforeTheColon.error === "forbiddenFrom",
        JSON.stringify(mailboxBeforeTheColon));
  check("nothing was delivered for the mailbox in front of the colon",
        mailboxBeforeTheColon.deliveredFrom === null);

  var addrSpecBeforeTheColon = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ceo@bank.example Authors: ops@example.com;",
  });
  check("a bare addr-spec in front of a group's colon is refused",
        addrSpecBeforeTheColon.created === false &&
        addrSpecBeforeTheColon.error === "forbiddenFrom",
        JSON.stringify(addrSpecBeforeTheColon));

  var namelessGroup = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: ": ops@example.com;",
  });
  check("a group with no display-name is refused",
        namelessGroup.created === false && namelessGroup.error === "forbiddenFrom",
        JSON.stringify(namelessGroup));

  // A colon is only a group opener where the grammar puts one. RFC 5322
  // section 3.2.2 ctext and section 3.2.4 qcontent both admit it, and
  // section 3.4.1 lets a domain be a bracketed literal whose IPv6 form is
  // written with colons. The domain-literal case is covered by the identity
  // I9 row above, which expects the message to go out.
  var colonInComment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Ops <ops@example.com> (see: elsewhere)",
  });
  check("a colon inside a comment does not open a group",
        colonInComment.created === true, JSON.stringify(colonInComment));

  var colonInDisplayName = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: '"Ops: the desk" <ops@example.com>',
  });
  check("a colon inside a quoted display name does not open a group",
        colonInDisplayName.created === true, JSON.stringify(colonInDisplayName));

  // And the mirror: a comma inside a comment is not a separator either, so a
  // legitimate message is not refused for carrying one.
  var commaInComment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Ops <ops@example.com> (a, b)",
  });
  check("a comma inside a comment is not a list separator",
        commaInComment.created === true, JSON.stringify(commaInComment));

  // Every escape the splitter honours skips two characters, and the last
  // character of the field is a place a sender can put the first of them. The
  // skip then lands past the end, the loop condition fails, and the segment
  // being accumulated is dropped instead of being read as a mailbox, so the
  // author it held is never checked while `deliver` still sends the header
  // verbatim. One appended byte, chosen by the sender.
  var trailingEscape = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, ceo@bank.example\\",
  });
  check("a trailing quoted-pair does not drop the author it precedes",
        trailingEscape.created === false && trailingEscape.error === "forbiddenFrom",
        JSON.stringify(trailingEscape));
  check("and nothing was delivered for it", trailingEscape.deliveredFrom === null);

  // The same skip inside a comment that the sender never closes.
  var openComment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, ceo@bank.example (x\\",
  });
  check("an unterminated comment ending in an escape does not drop the author",
        openComment.created === false && openComment.error === "forbiddenFrom",
        JSON.stringify(openComment));

  // And inside a quoted string the sender never closes.
  var openQuote = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: 'ops@example.com, "ceo" <ceo@bank.example> "x\\',
  });
  check("an unterminated quoted string ending in an escape does not drop the author",
        openQuote.created === false && openQuote.error === "forbiddenFrom",
        JSON.stringify(openQuote));

  // RFC 5322 section 3.6 lets From appear exactly once. The reader stopped at
  // the first one, so a message carrying two was authorized against whichever
  // the submitter put first while `deliver` sent both fields verbatim: the
  // same pair of authors was accepted or refused depending only on their
  // order, which is the submitter's to choose.
  var twoFromFields = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\nFrom: ceo@bank.example\r\n",
  });
  check("a second From field is not left unread",
        twoFromFields.created === false && twoFromFields.error === "forbiddenFrom",
        JSON.stringify(twoFromFields));

  var twoFromFieldsReversed = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ceo@bank.example\r\nFrom: ops@example.com\r\n",
  });
  check("and the order of the two does not change the answer",
        twoFromFieldsReversed.created === false &&
        twoFromFieldsReversed.error === "forbiddenFrom",
        JSON.stringify(twoFromFieldsReversed));

  // A segment the reader cannot turn into a mailbox was dropped, so an author
  // it could not read rode behind one it could. The module refuses a From it
  // cannot read at all, so refusing the part it cannot read is the same rule.
  var unreadableSegment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, <ceo@bank.example",
  });
  check("a segment that yields no mailbox is not skipped",
        unreadableSegment.created === false &&
        unreadableSegment.error === "forbiddenFrom",
        JSON.stringify(unreadableSegment));

  // And a segment whose content continues PAST the angle-addr: the reader
  // returned at the first `<...>` and never looked at the rest.
  var trailingInSegment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Ops <ops@example.com> ceo@bank.example",
  });
  check("a segment carrying an address after the angle-addr is not read as one author",
        trailingInSegment.created === false &&
        trailingInSegment.error === "forbiddenFrom",
        JSON.stringify(trailingInSegment));

  // RFC 5322 section 3.6.2 obs-mbox-list permits an empty element, so a
  // trailing comma is not an unreadable author and still goes out.
  var trailingComma = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, ",
  });
  check("a trailing comma is not treated as an unreadable author",
        trailingComma.created === true, JSON.stringify(trailingComma));

  // The reader accounted for the text AFTER the angle-addr and not the text
  // before it, so an address written where the display name goes was never
  // examined. RFC 5322 section 3.2.3 atext excludes `@`, so this is not a
  // conformant display-name and the module's rule is to refuse a From it
  // cannot read. The same-domain spelling is worse than a cross-domain one:
  // the envelope and the DKIM signature still align, so SPF, DKIM and DMARC
  // all pass at the receiver and nothing downstream is left to catch it.
  var addressBeforeAngle = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ceo@bank.example <ops@example.com>",
  });
  check("an address written where the display name goes is not left unread",
        addressBeforeAngle.created === false &&
        addressBeforeAngle.error === "forbiddenFrom",
        JSON.stringify(addressBeforeAngle));

  var sameDomainBeforeAngle = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "security@example.com <ops@example.com>",
  });
  check("and the aligned same-domain spelling of it is refused too",
        sameDomainBeforeAngle.created === false &&
        sameDomainBeforeAngle.error === "forbiddenFrom",
        JSON.stringify(sameDomainBeforeAngle));

  // A comment the sender never closes is not folding whitespace: the reader
  // cannot say what the rest of the element holds, and treating it as empty
  // let an author sit inside it.
  var hidingComment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Ops <ops@example.com> (hidden ceo@bank.example",
  });
  check("an unterminated comment is not read as empty whitespace",
        hidingComment.created === false && hidingComment.error === "forbiddenFrom",
        JSON.stringify(hidingComment));

  var openCommentSegment = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com, (hidden ceo@bank.example",
  });
  check("and the same inside a list element",
        openCommentSegment.created === false &&
        openCommentSegment.error === "forbiddenFrom",
        JSON.stringify(openCommentSegment));

  // RFC 5322 section 3.2.2 ctext runs %d33-39 / %d42-91 / %d93-126, which
  // contains `>`, so a comment inside the angle brackets may carry one. The
  // bracket scan modelled quoted strings and not comments, so it ended the
  // address early and refused a conformant author.
  var commentWithBracket = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Ops <ops(a>b)@example.com>",
  });
  check("a `>` inside a comment in the angle-addr does not end the address",
        commentWithBracket.created === true, JSON.stringify(commentWithBracket));

  // The header scan reads a bounded window, and a sender who fills it decides
  // which From field the gate sees. Reading part of the header block and
  // authorizing on it is the one answer that cannot be right: the fields it
  // did not reach are the ones an attacker puts the second author in. Every
  // line here is under the RFC 5322 section 2.1.1 998-byte cap.
  var padding = [];
  for (var padIndex = 0; padIndex < 900; padIndex += 1) {
    padding.push("X-Pad-" + padIndex + ": " + new Array(80).join("p"));
  }
  var beyondTheWindow = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\n" + padding.join("\r\n") +
                "\r\nFrom: ceo@bank.example\r\n",
  });
  check("a From field past the scan window is not silently unread",
        beyondTheWindow.created === false &&
        beyondTheWindow.error === "forbiddenFrom",
        JSON.stringify(beyondTheWindow));

  // Whitespace inside an address is folding whitespace only where the grammar
  // puts it: RFC 5322 section 3.2.3 has `dot-atom = [CFWS] dot-atom-text
  // [CFWS]`, so CFWS sits at an atom boundary and never between two atext
  // characters. Deleting every space glued `ops@example.co m` into
  // `ops@example.com` and authorized it, while a conformant reader takes the
  // domain as `example.co`: a lookalike the identity does not own, sent under
  // an identity that passes every alignment check for the other one.
  var gluedDomain = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.co m",
  });
  check("whitespace between two atext characters does not join them",
        gluedDomain.created === false && gluedDomain.error === "forbiddenFrom",
        JSON.stringify(gluedDomain));

  // The folded spelling is the same hole on the wire: unfolding removes the
  // CRLF and leaves the space (RFC 5322 section 2.2.3), and the bytes that go
  // out read `From: ops@example.co`.
  var gluedByFolding = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.co\r\n m\r\n",
  });
  check("and a folded header does not join them either",
        gluedByFolding.created === false && gluedByFolding.error === "forbiddenFrom",
        JSON.stringify(gluedByFolding));

  // Whitespace at the boundaries is still folding whitespace.
  var cfwsAroundAt = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "< ops @ example.com >",
  });
  check("whitespace at the atom boundaries is still ignored",
        cfwsAroundAt.created === true, JSON.stringify(cfwsAroundAt));

  // The header section has no size cap in RFC 5322 section 2.1.1, only a
  // 998-octet line cap, so a large one is conformant and its fields are read
  // rather than the reader stopping at a window and answering from the part
  // that fitted. Every line below is 900 bytes.
  var wide = [];
  for (var wideIndex = 0; wideIndex < 900; wideIndex += 1) {
    wide.push("X-Wide-" + wideIndex + ": " + new Array(870).join("w"));
  }
  var pastTheWindow = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\n" + wide.join("\r\n") +
                "\r\nFrom: ceo@bank.example\r\n",
  });
  check("a From field beyond any scan window is still read",
        pastTheWindow.created === false && pastTheWindow.error === "forbiddenFrom",
        JSON.stringify(pastTheWindow));

  // RFC 5322 section 2.1.1: "Each line of characters MUST be no more than 998
  // characters ... excluding the CRLF". `b.safeMime.parse` enforces that as
  // `maxHeaderLineBytes`, so a message carrying a longer line is one this
  // framework will not parse and `b.mailStore` will not store. The From gate
  // read the header section with no such bound, and the address reader walks a
  // field value one character at a time, so a single unfolded field carried
  // the whole cost of its length: measured through this handler, 16 MiB on one
  // line costs 772 ms against 71 ms for the same bytes folded at 900. The
  // refusal is by line length alone, so it does not depend on which field is
  // over-long.
  var overLongLine = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\nX-Pad: " +
                new Array(1200).join("p") + "\r\n",
  });
  check("a header line longer than RFC 5322 allows is refused",
        overLongLine.created === false, JSON.stringify(overLongLine));

  // The same bytes written the way the RFC says to write them are read.
  var foldedInstead = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\nX-Pad: " + new Array(600).join("p") +
                "\r\n " + new Array(600).join("p") + "\r\n",
  });
  check("and the same bytes folded onto conformant lines are still read",
        foldedInstead.created === true, JSON.stringify(foldedInstead));

  // The bound does not become a window: a second author past a long but
  // conformant header block is still found.
  var conformantWide = [];
  for (var cwIndex = 0; cwIndex < 200; cwIndex += 1) {
    conformantWide.push("X-Wide-" + cwIndex + ": " + new Array(900).join("w"));
  }
  var authorPastTheBound = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\n" + conformantWide.join("\r\n") +
                "\r\nFrom: ceo@bank.example\r\n",
  });
  check("a second author behind a long conformant header block is still checked",
        authorPastTheBound.created === false &&
        authorPastTheBound.error === "forbiddenFrom",
        JSON.stringify(authorPastTheBound));

  // A message with no body carries no blank line to separate one, which RFC
  // 5322 section 2.1 makes optional. Refusing it confused "I found no
  // separator" with "the header block was cut".
  var noBody = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    rawHeaders: "From: ops@example.com\r\nSubject: s\r\n",
  });
  check("a message with no body is not read as a truncated header block",
        noBody.created === true, JSON.stringify(noBody));

  // RFC 5322 section 3.2.2 writes `CFWS = (1*([FWS] comment) [FWS]) / FWS`, so
  // a comment and folding whitespace are one construct and section 3.2.3 puts
  // either only at an atom boundary. The boundary test went on the whitespace
  // branch alone, so the comment spelling of the same CFWS still glued two
  // atoms: `ops@example.co(x)m` read as `ops@example.com` and was authorized
  // while `ops@example.co m` was refused. No production reads the `m` into the
  // domain, since `dot-atom` stops at `example.co` and `obs-domain` requires a
  // "." after the atom the comment closes, so a conformant reader takes the
  // domain as `example.co`: the same lookalike the whitespace case was fixed
  // on, and the same-domain alignment that keeps SPF, DKIM and DMARC passing.
  var COMMENT_GLUE = [
    "ops@example.co(x)m",
    "op(x)s@example.com",
    "<ops@example.co(x)m>",
    "Ops <ops@example.co(x)m>",
    "ops@example.co (x) m",
    "ops@example.co(x)(y)m",
  ];
  var glued = [];
  for (var g = 0; g < COMMENT_GLUE.length; g += 1) {
    var byComment = await _submit({ identityId: "I1", mailFrom: "ops@example.com",
                                    fromHeader: COMMENT_GLUE[g] });
    if (byComment.created !== false || byComment.error !== "forbiddenFrom") {
      glued.push(COMMENT_GLUE[g] + " -> " +
                 (byComment.created ? "created" : byComment.error));
    }
  }
  check("a comment between two atext characters does not join them" +
        (glued.length ? " (" + glued.join("; ") + ")" : ""), glued.length === 0);

  // A comment AT a boundary is still folding whitespace, so the addresses real
  // agents write keep working.
  var BOUNDARY_COMMENTS = [
    "Ops <ops(work)@example.com>",
    "Ops <ops@(mail host)example.com>",
    "ops@example.com (work)",
    "(the sales desk) ops@example.com",
    "Ops <ops@example.com (work)>",
  ];
  var refusedAtBoundary = [];
  for (var bc = 0; bc < BOUNDARY_COMMENTS.length; bc += 1) {
    var atBoundary = await _submit({ identityId: "I1", mailFrom: "ops@example.com",
                                     fromHeader: BOUNDARY_COMMENTS[bc] });
    if (!atBoundary.created) {
      refusedAtBoundary.push(BOUNDARY_COMMENTS[bc] + " -> " + atBoundary.error);
    }
  }
  check("a comment at an atom boundary is still ignored" +
        (refusedAtBoundary.length ? " (" + refusedAtBoundary.join("; ") + ")" : ""),
        refusedAtBoundary.length === 0);

  // A nested comment closes at its own depth, not at the first `)`.
  var nested = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com (a (b, c) d), ceo@bank.example",
  });
  check("a nested comment does not end early and hide the second author",
        nested.created === false && nested.error === "forbiddenFrom",
        JSON.stringify(nested));
}

async function testAFoldedContinuationIsNotReadAsTheFromHeader() {
  // The scanner ran parseKeyValuePiece over every line, so a continuation of
  // some OTHER header — which RFC 5322 section 2.2.3 marks by leading
  // whitespace and nothing else — parsed as a field of its own. A sender
  // folding `From:` into the continuation of a header nobody checks put the
  // address the gate reads under their own control.
  // The forged continuation has to come BEFORE the real From, or the scanner
  // stops at the real one first and the row passes on the broken code too:
  // _message() prefixes "From: ", so putting the forgery after it measured
  // nothing. Here the first header is the one nobody checks, its continuation
  // carries the forged From, and the real From follows.
  var folded = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "ops@example.com",
    rawHeaders: "X-Note: see below\r\n From: ceo@bank.example\r\n" +
                "From: ops@example.com\r\n",
  });
  check("a continuation line is not read as the From header",
        folded.created === true && folded.deliveredFrom === "ops@example.com",
        JSON.stringify(folded));

  // And the real From header still folds: its own continuation is part of it.
  var realFold = await _submit({
    identityId: "I1", mailFrom: "ops@example.com",
    fromHeader: "Operations\r\n <ops@example.com>",
  });
  check("the From header's own continuation is still part of it",
        realFold.created === true && realFold.deliveredFrom === "ops@example.com",
        JSON.stringify(realFold));
}

async function run() {
  await testTheIdentityMatchIsNormalizedLikeSmtp();
  await testAQuotedDisplayNameDoesNotHijackTheAddress();
  await testTheFromHeaderIsCheckedToo();
  await testEveryMailboxOfAFromListIsChecked();
  await testAFoldedContinuationIsNotReadAsTheFromHeader();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-submission-sender] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
