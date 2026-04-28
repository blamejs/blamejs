"use strict";
/**
 * mail — message contract + pluggable transports.
 *
 * Both the contract and the transport surface ship together. Operators
 * can also pass any function or `{ send }` object as a custom transport.
 *
 *   mail.transports.console — logs message to stderr (dev default)
 *   mail.transports.memory  — captures into a `sent[]` array (tests)
 *   mail.transports.smtp    — raw RFC 5321 over net/tls with STARTTLS,
 *                             AUTH LOGIN, and PQC-friendly TLS opts
 *   mail.transports.http    — generic HTTP-API transport: operator
 *                             supplies endpoint, headers, serialize(),
 *                             and interpret() — works with any vendor
 *                             that speaks JSON-over-HTTPS (Postmark,
 *                             Mailgun, SES HTTP, SendGrid, Resend, …)
 *   mail.transports.resend  — thin preset that wires http to the
 *                             Resend API (illustrates the pattern)
 *
 * Public API:
 *
 *   mail.create({ transport?, defaults?, audit? }) → instance
 *
 *     transport — function(message) | { send(message) }; default: console.
 *     defaults  — { from, replyTo, headers, ... } merged into every
 *                 message unless the message overrides.
 *     audit     — emit mail.send.success / .failure audit events
 *                 (default true).
 *
 *   await instance.send(message)
 *     message: {
 *       to:       "x@y" | ["x@y", ...]
 *       cc:       string | string[]
 *       bcc:      string | string[]
 *       from:     "Name <noreply@app>"        (or instance default)
 *       replyTo:  "..."
 *       subject:  "..."
 *       text:     "plain body"                (at least one of text/html)
 *       html:     "<p>...</p>"
 *       headers:  { "X-Custom": "v" }         (merged with defaults)
 *     }
 *     → whatever the transport returned
 *
 * Validation surface uses MailError (FrameworkError subclass) with
 * permanent flag. Distinct codes per failure: missing-to, missing-from,
 * missing-body, invalid-recipient, transport-failed, smtp-*, http-*,
 * resend-*. Vendor-specific presets carry their own code prefix so
 * diagnostic logs identify the provider that rejected the message.
 */
var lazyRequire = require("./lazy-require");
var audit = lazyRequire(function () { return require("./audit"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });
var net = lazyRequire(function () { return require("net"); });
var tls = lazyRequire(function () { return require("tls"); });
var { FrameworkError } = require("./framework-error");

class MailError extends FrameworkError {
  constructor(code, message, permanent, statusCode) {
    super(message, code);
    this.name = "MailError";
    this.permanent = !!permanent;
    this.isMailError = true;
    if (typeof statusCode === "number") this.statusCode = statusCode;
  }
}

// Pragmatic email check — same shape as forms.validate. RFC 5322 in a
// regex is a fool's errand; this catches obvious nonsense and lets
// real-world addresses through.
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function _normalizeRecipientList(value, label) {
  if (value === undefined || value === null) return [];
  var arr = Array.isArray(value) ? value : [value];
  for (var i = 0; i < arr.length; i++) {
    if (typeof arr[i] !== "string" || arr[i].length === 0) {
      throw new MailError("mail/invalid-recipient",
        label + "[" + i + "] must be a non-empty string", true);
    }
    // CRLF/NUL in addresses → header injection. Reject hard.
    if (/[\r\n\0]/.test(arr[i])) {
      throw new MailError("mail/invalid-recipient",
        label + "[" + i + "] contains forbidden control characters", true);
    }
    // Accept "Name <email@addr>" form too — extract the angle-bracket
    // address for validation; preserve the full string in the message.
    var bracket = arr[i].match(/<([^>]+)>/);
    var addr = bracket ? bracket[1] : arr[i];
    if (!EMAIL_RE.test(addr.trim())) {
      throw new MailError("mail/invalid-recipient",
        label + " '" + arr[i] + "' is not a valid email address", true);
    }
  }
  return arr;
}

function _validateMessage(message) {
  if (!message || typeof message !== "object") {
    throw new MailError("mail/missing-message", "send() requires a message object", true);
  }
  var to = _normalizeRecipientList(message.to, "to");
  if (to.length === 0) {
    throw new MailError("mail/missing-to", "message.to is required (one or more recipients)", true);
  }
  _normalizeRecipientList(message.cc,  "cc");
  _normalizeRecipientList(message.bcc, "bcc");

  if (!message.from || typeof message.from !== "string") {
    throw new MailError("mail/missing-from", "message.from is required", true);
  }
  if (/[\r\n\0]/.test(message.from)) {
    throw new MailError("mail/invalid-from",
      "message.from contains forbidden control characters", true);
  }
  var fromBracket = message.from.match(/<([^>]+)>/);
  var fromAddr = fromBracket ? fromBracket[1] : message.from;
  if (!EMAIL_RE.test(fromAddr.trim())) {
    throw new MailError("mail/invalid-from",
      "message.from '" + message.from + "' is not a valid email address", true);
  }
  if (message.subject && /[\r\n]/.test(message.subject)) {
    throw new MailError("mail/invalid-subject",
      "message.subject contains forbidden CRLF", true);
  }

  if (!message.text && !message.html) {
    throw new MailError("mail/missing-body",
      "message must include at least one of text or html", true);
  }
}

function _mergeMessage(defaults, message) {
  // Per-message values override defaults; headers merged shallow.
  var merged = Object.assign({}, defaults || {}, message);
  if (defaults && defaults.headers && message.headers) {
    merged.headers = Object.assign({}, defaults.headers, message.headers);
  }
  return merged;
}

function _extractAddr(s) {
  if (s === undefined || s === null) return s;
  var m = String(s).match(/<([^>]+)>/);
  return m ? m[1].trim() : String(s).trim();
}

function _toArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v.slice() : [v];
}

// ---- Built-in transports: console + memory (dev / tests) ----

function consoleTransport(opts) {
  opts = opts || {};
  var stream = opts.stream || process.stderr;
  return {
    name: "console",
    send: async function (message) {
      var lines = [
        "[mail.console] To: " + (Array.isArray(message.to) ? message.to.join(", ") : message.to),
        "[mail.console] From: " + message.from,
        "[mail.console] Subject: " + (message.subject || ""),
      ];
      if (message.cc)  lines.push("[mail.console] Cc: " + (Array.isArray(message.cc)  ? message.cc.join(", ")  : message.cc));
      if (message.bcc) lines.push("[mail.console] Bcc: " + (Array.isArray(message.bcc) ? message.bcc.join(", ") : message.bcc));
      var body = message.text || (message.html ? "(html body, " + message.html.length + " bytes)" : "");
      lines.push("");
      lines.push(body);
      lines.push("");
      stream.write(lines.join("\n") + "\n");
      return { transport: "console", deliveredAt: Date.now() };
    },
  };
}

function memoryTransport() {
  var sent = [];
  return {
    name: "memory",
    sent: sent,
    send: async function (message) {
      sent.push(message);
      return { transport: "memory", deliveredAt: Date.now(), index: sent.length - 1 };
    },
    reset: function () { sent.length = 0; },
  };
}

// ---- SMTP transport ----
//
// Raw RFC 5321 state machine over net/tls. Multi-recipient (loops
// RCPT TO over to + cc + bcc), builds an RFC 5322 message with
// multipart/alternative when both text and html are supplied, and
// dot-stuffs body lines beginning with "." per SMTP transparency.
//
// PQC posture: TLS opts default to TLSv1.3 minimum and accept an
// `ecdhCurve` string (set to a hybrid PQC group such as
// "X25519MLKEM768" when peer + Node version support it). On a
// cleartext port the transport always issues STARTTLS and refuses
// to send AUTH or DATA in cleartext if the upgrade is rejected.

function _buildRfc822(message) {
  var headers = [];
  headers.push("From: " + message.from);
  headers.push("To: " + (Array.isArray(message.to) ? message.to.join(", ") : message.to));
  if (message.cc)      headers.push("Cc: " + (Array.isArray(message.cc) ? message.cc.join(", ") : message.cc));
  if (message.replyTo) headers.push("Reply-To: " + message.replyTo);
  if (message.subject) headers.push("Subject: " + message.subject);
  headers.push("MIME-Version: 1.0");
  headers.push("Date: " + new Date().toUTCString());
  if (message.headers) {
    for (var k in message.headers) {
      if (Object.prototype.hasOwnProperty.call(message.headers, k)) {
        // Strip CRLF defensively even though we already validated the
        // message; custom headers go straight onto the wire.
        var v = String(message.headers[k]).replace(/[\r\n]/g, "");
        headers.push(k + ": " + v);
      }
    }
  }

  var body;
  if (message.text && message.html) {
    var boundary = "blamejs-mail-" + Date.now() + "-" + Math.floor(Math.random() * 1e9);
    headers.push('Content-Type: multipart/alternative; boundary="' + boundary + '"');
    body = [
      "--" + boundary,
      "Content-Type: text/plain; charset=utf-8",
      "",
      message.text,
      "--" + boundary,
      "Content-Type: text/html; charset=utf-8",
      "",
      message.html,
      "--" + boundary + "--",
    ].join("\r\n");
  } else if (message.html) {
    headers.push("Content-Type: text/html; charset=utf-8");
    body = message.html;
  } else {
    headers.push("Content-Type: text/plain; charset=utf-8");
    body = message.text || "";
  }

  // Normalize line endings then dot-stuff per SMTP transparency.
  body = body.replace(/\r?\n/g, "\r\n");
  body = body.split("\r\n").map(function (l) { return l.charAt(0) === "." ? "." + l : l; }).join("\r\n");

  return headers.join("\r\n") + "\r\n\r\n" + body;
}

function smtpTransport(opts) {
  opts = opts || {};
  if (!opts.host) {
    throw new MailError("mail/smtp-misconfigured",
      "smtp transport requires opts.host", true);
  }
  var port = opts.port || 587;
  var useImplicitTLS = port === 465 || opts.implicitTls === true;
  var rejectUnauthorized = opts.rejectUnauthorized !== false;
  var ehloName = opts.ehloName || "blamejs";
  var timeoutMs = opts.timeoutMs || 15000;
  var tlsOpts = {
    rejectUnauthorized: rejectUnauthorized,
    minVersion: opts.minTlsVersion || "TLSv1.3",
  };
  if (opts.ecdhCurve) tlsOpts.ecdhCurve = opts.ecdhCurve;
  if (opts.ca)        tlsOpts.ca = opts.ca;

  var cfg = {
    host:           opts.host,
    port:           port,
    user:           opts.user,
    pass:           opts.pass,
    useImplicitTLS: useImplicitTLS,
    ehloName:       ehloName,
    timeoutMs:      timeoutMs,
    tlsOpts:        tlsOpts,
  };

  return {
    name: "smtp",
    send: function (message) { return _smtpSend(message, cfg); },
  };
}

function _smtpSend(message, cfg) {
  return new Promise(function (resolve, reject) {
    var socket;
    var step = 0;
    var buffer = "";
    var upgradedToTLS = false;
    var settled = false;
    var lastCode = 0;
    var rcptIndex = 0;

    var fromAddr = _extractAddr(message.from);
    var toList   = _toArray(message.to).map(_extractAddr);
    var ccList   = _toArray(message.cc).map(_extractAddr);
    var bccList  = _toArray(message.bcc).map(_extractAddr);
    var rcpts    = toList.concat(ccList, bccList);
    var dataMessage = _buildRfc822(message);

    function fail(reason) {
      if (settled) return;
      settled = true;
      try { if (socket) socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
      reject(new MailError("mail/smtp-failed",
        "SMTP send failed: " + reason, false));
    }
    function done(ok, code) {
      if (settled) return;
      settled = true;
      try { socket.end(); } catch (_e) { /* socket may already be torn down */ }
      if (ok) resolve({ transport: "smtp", deliveredAt: Date.now(), code: code });
      else reject(new MailError("mail/smtp-rejected",
        "SMTP rejected message (code " + code + ")", false));
    }

    function send(cmd) {
      try { socket.write(cmd + "\r\n"); }
      catch (e) { fail(e.message || String(e)); }
    }

    function onData(data) {
      buffer += data;
      var lines = buffer.split("\r\n");
      buffer = lines.pop();
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line) continue;
        var code = parseInt(line.slice(0, 3), 10);
        if (line[3] === "-") continue; // continuation line
        lastCode = code;
        try { handleResponse(code); }
        catch (e) { fail(e.message || String(e)); return; }
        if (settled) return;
      }
    }

    function attachSocket(s) {
      socket = s;
      socket.setEncoding("utf8");
      socket.setTimeout(cfg.timeoutMs);
      socket.on("data", onData);
      socket.on("error", function (err) { fail(err.message || String(err)); });
      socket.on("timeout", function () { fail("timeout"); });
    }

    function connect() {
      if (cfg.useImplicitTLS) {
        var tlsConnectOpts = Object.assign({ servername: cfg.host }, cfg.tlsOpts);
        attachSocket(tls().connect(cfg.port, cfg.host, tlsConnectOpts));
      } else {
        attachSocket(net().createConnection(cfg.port, cfg.host));
      }
    }

    function handleResponse(code) {
      if (step === 0) {
        if (code !== 220) { fail("greeting-rejected (code " + code + ")"); return; }
        send("EHLO " + cfg.ehloName); step = 1;
      }
      else if (step === 1) {
        if (code < 200 || code >= 300) { fail("ehlo-rejected (code " + code + ")"); return; }
        if (!cfg.useImplicitTLS && !upgradedToTLS) { send("STARTTLS"); step = 10; }
        else if (cfg.user) { send("AUTH LOGIN"); step = 2; }
        else { send("MAIL FROM:<" + fromAddr + ">"); step = 5; }
      }
      else if (step === 10) {
        if (code !== 220) { fail("starttls-rejected (code " + code + ")"); return; }
        var tlsConnectOpts = Object.assign({ socket: socket, servername: cfg.host }, cfg.tlsOpts);
        var tlsSocket = tls().connect(tlsConnectOpts, function () {
          upgradedToTLS = true;
          try { socket.removeAllListeners("data"); } catch (_e) { /* listeners migrate to upgraded socket */ }
          attachSocket(tlsSocket);
          send("EHLO " + cfg.ehloName);
          step = 1;
        });
        tlsSocket.on("error", function (err) {
          fail("tls-upgrade: " + (err.message || String(err)));
        });
      }
      else if (step === 2) {
        if (code !== 334) { fail("auth-username-rejected (code " + code + ")"); return; }
        send(Buffer.from(cfg.user || "").toString("base64")); step = 3;
      }
      else if (step === 3) {
        if (code !== 334) { fail("auth-password-rejected (code " + code + ")"); return; }
        send(Buffer.from(cfg.pass || "").toString("base64")); step = 4;
      }
      else if (step === 4) {
        if (code !== 235) { fail("auth-failed (code " + code + ")"); return; }
        send("MAIL FROM:<" + fromAddr + ">"); step = 5;
      }
      else if (step === 5) {
        if (code < 200 || code >= 300) { fail("mail-from-rejected (code " + code + ")"); return; }
        send("RCPT TO:<" + rcpts[rcptIndex++] + ">"); step = 6;
      }
      else if (step === 6) {
        if (code < 200 || code >= 300) { fail("rcpt-rejected (code " + code + ")"); return; }
        if (rcptIndex < rcpts.length) {
          send("RCPT TO:<" + rcpts[rcptIndex++] + ">");
        } else {
          send("DATA"); step = 7;
        }
      }
      else if (step === 7) {
        if (code !== 354) { fail("data-rejected (code " + code + ")"); return; }
        send(dataMessage + "\r\n.");
        step = 8;
      }
      else if (step === 8) {
        var ok = code === 250;
        done(ok, code);
      }
    }

    try { connect(); }
    catch (e) { fail(e.message || String(e)); }
  });
}

// ---- Generic HTTP transport ----
//
// Vendor-agnostic transport for any mail API that speaks HTTP. Operators
// supply three things: an endpoint, a serialize() that turns the
// framework-shaped message into the vendor's request body + headers,
// and an interpret() that reads the vendor's response and decides
// success vs failure. Uses lib/http-client so PQC TLS, response caps,
// and timeout handling come for free.
//
//   httpTransport({
//     name:             "postmark",            // appears in result + error codes
//     endpoint:         "https://...",         // POST target
//     method:           "POST",                // default POST
//     headers:          { ... },               // base headers (auth, content-type, ...)
//     timeoutMs:        15000,
//     allowedProtocols: safeUrl.ALLOW_HTTP_TLS, // default HTTPS-only
//     serialize: function (message) {
//       // → { headers?: {...}, body: string | Buffer }
//     },
//     interpret: function (res, message) {
//       // res = { statusCode, headers, body: Buffer }
//       // → { ok: true, id?: "..." } | { ok: false, reason: "..." }
//       // throw a MailError for permanent / structural failures
//     },
//   })
//
// Errors carry a `mail/<name>-*` code so logs identify which provider
// rejected which message (mail/postmark-failed, mail/resend-rejected,
// etc.). HTTPS-only is the default — pass safeUrl.ALLOW_HTTP_ALL via
// opts.allowedProtocols only for local test fixtures.

function httpTransport(opts) {
  opts = opts || {};
  if (!opts.endpoint || typeof opts.endpoint !== "string") {
    throw new MailError("mail/http-misconfigured",
      "http transport requires opts.endpoint", true);
  }
  if (typeof opts.serialize !== "function") {
    throw new MailError("mail/http-misconfigured",
      "http transport requires opts.serialize(message) → { headers?, body }", true);
  }
  var name             = opts.name || "http";
  var method           = (opts.method || "POST").toUpperCase();
  var endpoint         = opts.endpoint;
  var baseHeaders      = opts.headers || {};
  var timeoutMs        = opts.timeoutMs || 15000;
  var allowedProtocols = opts.allowedProtocols || null;
  var interpret        = typeof opts.interpret === "function" ? opts.interpret : null;
  var serialize        = opts.serialize;
  var codePrefix       = "mail/" + name;

  return {
    name: name,
    send: async function (message) {
      var serialized = serialize(message);
      if (!serialized || typeof serialized !== "object") {
        throw new MailError(codePrefix + "-bad-serializer",
          "serialize() must return { headers?, body }", false);
      }
      var body = serialized.body;
      if (typeof body === "string") body = Buffer.from(body, "utf8");
      if (!Buffer.isBuffer(body)) {
        throw new MailError(codePrefix + "-bad-serializer",
          "serialize() body must be a string or Buffer", false);
      }
      var headers = Object.assign({}, baseHeaders, serialized.headers || {});
      // Default Content-Length when caller hasn't asserted chunked
      // transfer; keeps small JSON payloads from being chunked needlessly.
      var hasLen = false;
      for (var hk in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, hk) &&
            hk.toLowerCase() === "content-length") { hasLen = true; break; }
      }
      if (!hasLen) headers["Content-Length"] = body.length;

      var reqOpts = {
        method:     method,
        url:        endpoint,
        headers:    headers,
        body:       body,
        timeoutMs:  timeoutMs,
        errorClass: MailError, // http-client constructs (code, message, permanent, statusCode)
      };
      if (allowedProtocols) reqOpts.allowedProtocols = allowedProtocols;

      var res;
      try {
        res = await httpClient().request(reqOpts);
      } catch (e) {
        // http-client constructs a MailError via opts.errorClass on
        // non-2xx / network / timeout, with its own code domain
        // (HTTP_ERROR, ETIMEDOUT, ...). Rewrap into mail/<name>-failed
        // so the consumer-facing code identifies the provider while
        // preserving the original as `cause` and the HTTP statusCode.
        var wrapped = new MailError(codePrefix + "-failed",
          name + " request failed: " + ((e && e.message) || String(e)),
          false,
          e && typeof e.statusCode === "number" ? e.statusCode : undefined);
        wrapped.cause = e;
        throw wrapped;
      }

      var info = { transport: name, deliveredAt: Date.now() };
      if (typeof res.statusCode === "number") info.statusCode = res.statusCode;

      if (!interpret) return info;

      var verdict;
      try { verdict = interpret(res, message); }
      catch (e) {
        if (e && e.isMailError) throw e;
        throw new MailError(codePrefix + "-interpret-failed",
          "interpret() threw: " + ((e && e.message) || String(e)), false);
      }
      if (!verdict || verdict.ok === false) {
        var reason = (verdict && verdict.reason) || "rejected";
        var err = new MailError(codePrefix + "-rejected",
          name + " rejected message: " + reason, false);
        if (verdict && typeof verdict.statusCode === "number") err.statusCode = verdict.statusCode;
        throw err;
      }
      if (verdict.id)    info.id = verdict.id;
      if (verdict.extra) Object.assign(info, verdict.extra);
      return info;
    },
  };
}

// ---- Resend preset ----
//
// Thin convenience wrapper that wires httpTransport to Resend's API.
// Operators wanting Postmark / Mailgun / SES HTTP / SendGrid build the
// same shape against httpTransport directly — this preset exists to
// document the pattern, not to privilege any single vendor.

function resendTransport(opts) {
  opts = opts || {};
  if (!opts.apiKey || typeof opts.apiKey !== "string") {
    throw new MailError("mail/resend-misconfigured",
      "resend transport requires opts.apiKey", true);
  }
  return httpTransport({
    name:             "resend",
    endpoint:         opts.endpoint || "https://api.resend.com/emails",
    method:           "POST",
    timeoutMs:        opts.timeoutMs || 15000,
    allowedProtocols: opts.allowedProtocols || null,
    headers: {
      "Authorization": "Bearer " + opts.apiKey,
      "Content-Type":  "application/json",
    },
    serialize: function (message) {
      var payload = {
        from:    message.from,
        to:      Array.isArray(message.to) ? message.to : [message.to],
        subject: message.subject || "",
      };
      if (message.cc)      payload.cc       = Array.isArray(message.cc)  ? message.cc  : [message.cc];
      if (message.bcc)     payload.bcc      = Array.isArray(message.bcc) ? message.bcc : [message.bcc];
      if (message.replyTo) payload.reply_to = message.replyTo;
      if (message.html)    payload.html     = message.html;
      if (message.text)    payload.text     = message.text;
      if (message.headers) payload.headers  = message.headers;
      return { body: JSON.stringify(payload) };
    },
    interpret: function (res) {
      var text = res.body ? res.body.toString("utf8") : "";
      var data;
      try { data = JSON.parse(text); }
      catch (_e) {
        throw new MailError("mail/resend-bad-response",
          "resend response was not JSON: " + text.slice(0, 200), false);
      }
      if (!data.id) {
        return {
          ok:     false,
          reason: data.message || JSON.stringify(data).slice(0, 200),
        };
      }
      return { ok: true, id: data.id };
    },
  });
}

// ---- Engine instance ----

function create(opts) {
  opts = opts || {};
  var transport = opts.transport || consoleTransport();
  if (typeof transport === "function") {
    transport = { send: transport, name: "anonymous" };
  }
  if (!transport || typeof transport.send !== "function") {
    throw new MailError("mail/bad-transport",
      "opts.transport must be a function or an object with .send(message)", true);
  }
  var defaults = opts.defaults || {};
  var auditOn = opts.audit !== false;

  function _emit(action, info) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  info.outcome || (action.endsWith(".failure") ? "failure" : "success"),
      actor:    info.actor || {},
      // Recipient COUNT, not addresses — addresses can be PII; the
      // framework's audit chain shouldn't carry them by default.
      // Operators who need full address logging set their own audit
      // hook with whatever PII discipline they want.
      metadata: {
        transport:     transport.name || "custom",
        subject:       info.subject || "",
        toCount:       info.toCount,
        ccCount:       info.ccCount,
        bccCount:      info.bccCount,
        durationMs:    info.durationMs,
      },
      reason:   info.reason || null,
    });
  }

  async function send(message) {
    var merged = _mergeMessage(defaults, message);
    _validateMessage(merged);

    var t0 = Date.now();
    try {
      var result = await transport.send(merged);
      _emit("mail.send.success", {
        subject:    merged.subject,
        toCount:    Array.isArray(merged.to)  ? merged.to.length  : 1,
        ccCount:    Array.isArray(merged.cc)  ? merged.cc.length  : (merged.cc  ? 1 : 0),
        bccCount:   Array.isArray(merged.bcc) ? merged.bcc.length : (merged.bcc ? 1 : 0),
        durationMs: Date.now() - t0,
      });
      return result;
    } catch (e) {
      _emit("mail.send.failure", {
        subject:    merged.subject,
        toCount:    Array.isArray(merged.to)  ? merged.to.length  : 1,
        ccCount:    Array.isArray(merged.cc)  ? merged.cc.length  : (merged.cc  ? 1 : 0),
        bccCount:   Array.isArray(merged.bcc) ? merged.bcc.length : (merged.bcc ? 1 : 0),
        durationMs: Date.now() - t0,
        outcome:    "failure",
        reason:     (e && e.message) || String(e),
      });
      // Re-throw as MailError when the upstream wasn't already one,
      // preserving the cause for diagnostic chains.
      if (e && e.isMailError) throw e;
      var wrapped = new MailError("mail/transport-failed",
        "transport '" + (transport.name || "custom") + "' failed: " + ((e && e.message) || String(e)),
        false);
      wrapped.cause = e;
      throw wrapped;
    }
  }

  return {
    send:      send,
    transport: transport,
    defaults:  defaults,
  };
}

module.exports = {
  create:     create,
  MailError:  MailError,
  transports: {
    console: consoleTransport,
    memory:  memoryTransport,
    smtp:    smtpTransport,
    http:    httpTransport,
    resend:  resendTransport,
  },
};
