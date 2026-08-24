// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * DANE peer authentication, end to end over real sockets.
 *
 * Every layer-0 DANE test in this repo hands the transport a TLSA record it
 * built itself, which proves the matcher and nothing else. In particular it
 * cannot prove that `b.network.dns` DECODES a TLSA record into the fields the
 * DANE path reads: a stub written to agree with a reading of the decoder
 * agrees with the reading, not with the decoder.
 *
 * This drives the whole chain with nothing mocked but the zone contents, which
 * have to be synthetic — nobody can publish TLSA for a domain they do not own:
 *
 *   b.mail.send.deliver
 *     → MX lookup      -> real DoH request over real TLS to a DNS server here
 *     → TLSA lookup    -> the same, answered with real wire-format bytes
 *     → safeDns decode -> the framework's own parser, on those bytes
 *     → TLS handshake  -> real, against an SMTP peer presenting a real cert
 *     → verifyChain    -> the presented chain against the published records
 *
 * The DNS responses are assembled here as raw RFC 1035 wire format rather than
 * as objects, so the framework's parser is what turns them back into records.
 * That is the point of the file.
 *
 * Run: node scripts/test-integration.js mail-dane-authentication
 */

var nodeCrypto = require("node:crypto");
var nodeHttps  = require("node:https");
var nodeTls    = require("node:tls");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- RFC 1035 wire format ------------------------------------------------

var RTYPE_MX   = 15;
var RTYPE_TLSA = 52;

// A domain name as length-prefixed labels terminated by a zero octet. No
// compression pointers: the responses here are small, and an uncompressed name
// is the form every parser must accept.
function _encodeName(name) {
  var parts = String(name).replace(/\.$/, "").split(".");                        // allow:regex-no-length-cap — trailing-dot trim on a test fixture name
  var out = [];
  for (var i = 0; i < parts.length; i += 1) {
    var label = Buffer.from(parts[i], "ascii");
    out.push(Buffer.from([label.length]));
    out.push(label);
  }
  out.push(Buffer.from([0]));
  return Buffer.concat(out);
}

function _decodeName(buf, offset) {
  var labels = [];
  var off = offset;
  while (off < buf.length) {
    var len = buf[off];
    if (len === 0) { off += 1; break; }
    labels.push(buf.subarray(off + 1, off + 1 + len).toString("ascii"));
    off += 1 + len;
  }
  return { name: labels.join("."), end: off };
}

// Read the ID, question name and qtype out of a client query.
function _parseQuery(buf) {
  var id = buf.readUInt16BE(0);
  var q = _decodeName(buf, 12);
  return { id: id, name: q.name, qtype: buf.readUInt16BE(q.end), questionEnd: q.end + 4 };
}

function _rr(name, rtype, ttl, rdata) {
  var head = Buffer.alloc(10);
  head.writeUInt16BE(rtype, 0);
  head.writeUInt16BE(1, 2);                                                      // IN
  head.writeUInt32BE(ttl, 4);
  head.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([_encodeName(name), head, rdata]);
}

// A response echoing the question, with QR + AA + RD + RA set.
function _buildResponse(query, buf, answers) {
  var header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  header.writeUInt16BE(0x8580, 2);                                               // QR=1 AA=1 RD=1 RA=1, RCODE=0
  header.writeUInt16BE(1, 4);                                                    // QDCOUNT
  header.writeUInt16BE(answers.length, 6);                                       // ANCOUNT
  return Buffer.concat([header, buf.subarray(12, query.questionEnd)].concat(answers));
}

function _mxRdata(preference, exchange) {
  var pref = Buffer.alloc(2);
  pref.writeUInt16BE(preference, 0);
  return Buffer.concat([pref, _encodeName(exchange)]);
}

// RFC 6698 §2.1 — usage, selector, matching type, then the association data.
function _tlsaRdata(usage, selector, matchingType, assoc) {
  return Buffer.concat([Buffer.from([usage, selector, matchingType]), assoc]);
}

// ---- fixtures ------------------------------------------------------------

function _certDer(pem) {
  var body = String(pem)
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "");                                                        // allow:regex-no-length-cap — whitespace strip on a local PEM fixture
  return Buffer.from(body, "base64");
}

// A DoH endpoint over real TLS, answering from a table the test controls.
// GET ?dns=<base64url query>, which is the form the framework's resolver emits.
// RFC 8484 allows both forms: GET with a base64url `dns` parameter, and POST
// with the wire query as the body. `useDnsOverHttps({ method })` selects one,
// and an endpoint that only accepts POST is a real deployment — so the server
// here answers both and records which was used.
function _startDohServer(certPair, zone, seen) {
  var server = nodeHttps.createServer(
    { key: certPair.key, cert: certPair.cert },
    function (req, res) {
      function _answer(qbuf) {
        var query = _parseQuery(qbuf);
        seen.push({ name: query.name, qtype: query.qtype, method: req.method });
        var key = query.name.toLowerCase() + "/" + query.qtype;
        var answers = (zone[key] || []).map(function (a) {
          return _rr(query.name, query.qtype, 300, a);
        });
        res.setHeader("Content-Type", "application/dns-message");
        res.end(_buildResponse(query, qbuf, answers));
      }
      if (req.method === "POST") {
        var chunks = [];
        req.on("data", function (c) { chunks.push(c); });
        req.on("end", function () { _answer(Buffer.concat(chunks)); });
        return;
      }
      var qs = req.url.indexOf("?") === -1 ? "" : req.url.slice(req.url.indexOf("?") + 1);
      var dns = null;
      qs.split("&").forEach(function (pair) {
        if (pair.indexOf("dns=") === 0) dns = pair.slice(4);
      });
      if (!dns) { res.statusCode = 400; res.end(); return; }
      _answer(Buffer.from(dns.replace(/-/g, "+").replace(/_/g, "/"), "base64"));  // allow:regex-no-length-cap — base64url -> base64 on a bounded query
    });
  return server;
}

// An SMTP peer that upgrades on STARTTLS, which is the shape RFC 7672 DANE is
// defined for: a receiving MX on port 25 offering STARTTLS, authenticated by
// its TLSA records rather than by a public CA.
function _startSmtpWithStartTls(certPair, accepted) {
  return require("node:net").createServer(function (raw) {
    raw.on("error", function () {});
    raw.write("220 dane-peer ESMTP\r\n");
    _wire(raw, false);

    function _wire(sock, secure) {
      var buf = "";
      var inData = false;
      sock.setEncoding("utf8");
      sock.on("error", function () {});
      sock.on("data", function onData(chunk) {
        buf += chunk;
        while (true) {
          if (inData) {
            var end = buf.indexOf("\r\n.\r\n");
            if (end === -1) return;
            accepted.push(buf.slice(0, end));
            buf = buf.slice(end + 5);
            inData = false;
            sock.write("250 2.6.0 accepted\r\n");
            continue;
          }
          var nl = buf.indexOf("\r\n");
          if (nl === -1) return;
          var line = buf.slice(0, nl);
          buf = buf.slice(nl + 2);
          var upper = line.toUpperCase();
          if (upper.indexOf("EHLO") === 0) {
            sock.write(secure ? "250 dane-peer\r\n" : "250-dane-peer\r\n250 STARTTLS\r\n");
          } else if (upper.indexOf("STARTTLS") === 0 && !secure) {
            sock.write("220 ready\r\n");
            sock.removeListener("data", onData);
            var upgraded = new nodeTls.TLSSocket(sock, {
              isServer: true, key: certPair.key, cert: certPair.cert,
            });
            _wire(upgraded, true);
            return;
          } else if (upper.indexOf("DATA") === 0) {
            inData = true; sock.write("354 go\r\n");
          } else if (upper.indexOf("QUIT") === 0) {
            sock.write("221 bye\r\n");
          } else {
            sock.write("250 ok\r\n");
          }
        }
      });
    }
  });
}

function _listen(server) {
  return new Promise(function (resolve, reject) {
    server.listen(0, "127.0.0.1", function () { resolve(server.address().port); });
    server.on("error", reject);
  });
}

function _close(server) {
  return new Promise(function (resolve) {
    try { server.close(function () { resolve(); }); } catch (_e) { resolve(); }
  });
}

// ---- the run -------------------------------------------------------------

async function run() {
  var ca   = await b.mtlsEngine.generateCa({ name: "dane-integration-ca" });
  var doh  = await b.mtlsEngine.signClientCert({
    cn: "localhost", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:localhost", "IP:127.0.0.1"], validityDays: 1,
  });
  var peer = await b.mtlsEngine.signClientCert({
    cn: "mx.dane.test", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
    usage: "server", sans: ["DNS:mx.dane.test", "DNS:localhost", "IP:127.0.0.1"],
    validityDays: 1,
  });

  // The record the peer's operator would publish: DANE-EE, full certificate,
  // SHA-256. Computed from the certificate this peer actually presents, so a
  // match means the framework compared the two rather than waving it through.
  var peerDer   = _certDer(peer.cert);
  var peerSha   = nodeCrypto.createHash("sha256").update(peerDer).digest();
  var smtpAccepted = [];
  var smtpServer = _startSmtpWithStartTls(peer, smtpAccepted);
  var smtpPort   = await _listen(smtpServer);

  // MX for the recipient domain, TLSA for the MX host at the SMTP port.
  //
  // The MX host is `localhost` because the transport connects to it by name
  // through the OS resolver, as it would to a real MX. Only the zone served
  // here is synthetic; the socket, the handshake and the lookups are not.
  var MX_HOST = "localhost";
  var zone = {};
  zone["dane.test/" + RTYPE_MX] = [_mxRdata(10, MX_HOST)];
  zone["_" + smtpPort + "._tcp." + MX_HOST + "/" + RTYPE_TLSA] =
    [_tlsaRdata(3, 0, 1, peerSha)];

  var seen = [];
  var dohServer = _startDohServer(doh, zone, seen);
  var dohPort   = await _listen(dohServer);

  try {
    b.network.dns.useDnsOverHttps({
      url: "https://127.0.0.1:" + dohPort + "/dns-query",
      method: "GET",
      ca: ca.caCertPem,
    });

    var resolver = b.network.dns.resolver.create({ profile: "permissive" });

    // First: prove the framework's own parser decodes the TLSA bytes. This is
    // the link every layer-0 test takes on faith, because a stub written to a
    // shape agrees with whoever wrote it.
    var tlsaRv = await resolver.queryTlsa("_" + smtpPort + "._tcp." + MX_HOST);
    check("live DNS: a TLSA answer decodes to one record",
          tlsaRv && Array.isArray(tlsaRv.rrs) && tlsaRv.rrs.length === 1,
          JSON.stringify(tlsaRv && tlsaRv.rrs));
    var dec = tlsaRv.rrs[0].decoded;
    check("live DNS: TLSA decodes into usage / selector / matchingType / certData",
          dec && dec.usage === 3 && dec.selector === 0 && dec.matchingType === 1 &&
          Buffer.isBuffer(dec.certData) && dec.certData.equals(peerSha),
          JSON.stringify(dec && { u: dec.usage, s: dec.selector, m: dec.matchingType,
                                  len: dec.certData && dec.certData.length }));

    // Then the whole path: MX lookup, TLSA fetch, handshake, chain match.
    var deliver = b.mail.send.deliver({
      hostname: "mta.dane.test",
      port:     smtpPort,
      resolver: resolver,
      policy:   { mtaSts: "off", dane: "enforce", dnssecValidated: true },
      audit:    false,
    });
    var rv = await deliver({
      from:   "ops@dane.test",
      to:     ["alice@dane.test"],
      rfc822: Buffer.from("Subject: dane\r\n\r\nhello\r\n", "utf8"),
    });
    check("DANE end to end: the message was delivered",
          rv.delivered.length === 1 && rv.failed.length === 0,
          JSON.stringify({ d: rv.delivered.length, df: rv.deferred.length,
                           f: rv.failed.length,
                           why: (rv.deferred[0] || rv.failed[0] || {}).reason }));
    check("DANE end to end: the peer received the body",
          smtpAccepted.length === 1 && smtpAccepted[0].indexOf("hello") !== -1,
          JSON.stringify(smtpAccepted));
    check("DANE end to end: both lookups went over the wire",
          seen.some(function (q) { return q.qtype === RTYPE_MX; }) &&
          seen.some(function (q) { return q.qtype === RTYPE_TLSA; }),
          JSON.stringify(seen));

    // The control, and the only thing that makes the pass above mean anything:
    // publish a record the peer's certificate does NOT match, change nothing
    // else, and the same delivery must be refused.
    var wrong = Buffer.from(peerSha);
    wrong[0] = wrong[0] ^ 0xff;
    zone["_" + smtpPort + "._tcp." + MX_HOST + "/" + RTYPE_TLSA] =
      [_tlsaRdata(3, 0, 1, wrong)];
    resolver.clearCache();

    var rv2 = await deliver({
      from:   "ops@dane.test",
      to:     ["bob@dane.test"],
      rfc822: Buffer.from("Subject: dane\r\n\r\nhello\r\n", "utf8"),
    });
    check("DANE end to end: a non-matching published record refuses delivery",
          rv2.delivered.length === 0,
          JSON.stringify({ d: rv2.delivered.length, df: rv2.deferred.length,
                           f: rv2.failed.length }));
    check("DANE end to end: the refusal defers rather than bouncing",
          rv2.deferred.length === 1 && rv2.failed.length === 0,
          JSON.stringify({ df: rv2.deferred.length, f: rv2.failed.length }));
    check("DANE end to end: the peer never saw the second message",
          smtpAccepted.length === 1, JSON.stringify(smtpAccepted.length));

    // RFC 8484 §4.1 — a DoH endpoint may accept only POST, and
    // `useDnsOverHttps({ method: "POST" })` says so. Honouring the operator's
    // URL while ignoring their method leaves that endpoint unusable, which
    // takes the resolver — and everything built on it — down with it.
    seen.length = 0;
    b.network.dns.useDnsOverHttps({
      url:    "https://127.0.0.1:" + dohPort + "/dns-query",
      method: "POST",
      ca:     ca.caCertPem,
    });
    var postResolver = b.network.dns.resolver.create({ profile: "permissive" });
    var postRv = await postResolver.queryMx("dane.test");
    check("DoH POST: the query reached the endpoint as a POST",
          seen.length > 0 && seen[0].method === "POST", JSON.stringify(seen));
    check("DoH POST: the answer decoded",
          postRv && postRv.rrs.length === 1 &&
          postRv.rrs[0].decoded.exchange === MX_HOST,
          JSON.stringify(postRv && postRv.rrs.map(function (r) { return r.decoded; })));
  } finally {
    await _close(dohServer);
    await _close(smtpServer);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    process.stdout.write("OK — " + helpers.getChecks() + " checks passed\n");
  }).catch(function (e) {
    process.stderr.write("FAIL: " + ((e && e.stack) || e) + "\n");
    process.exit(1);
  });
}
