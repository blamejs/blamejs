"use strict";

var tls = require("node:tls");
var dgram = require("node:dgram");
var nodeCrypto = require("node:crypto");

var C = require("./constants");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var NtsError = defineClass("NtsError", { alwaysPermanent: false });

var NTS_KE_DEFAULT_PORT = 4460;
var NTPV4_DEFAULT_PORT  = 123;
var NTP_TO_UNIX_OFFSET_SECONDS = 2208988800;

var REC_END                  = 0;
var REC_NEXT_PROTOCOL        = 1;
var REC_ERROR                = 2;
var REC_WARNING              = 3;
var REC_AEAD_ALGORITHM       = 4;
var REC_NEW_COOKIE           = 5;
var REC_NTPV4_SERVER         = 6;
var REC_NTPV4_PORT           = 7;

var NTPV4_PROTOCOL_ID = 0;

var AEAD_AES_SIV_CMAC_256    = 15;
var AEAD_CHACHA20_POLY1305   = 30;

var EXTENSION_UNIQUE_IDENTIFIER         = 0x0104;
var EXTENSION_NTS_COOKIE                 = 0x0204;
var EXTENSION_NTS_AUTHENTICATOR_AND_ENC  = 0x0404;

function _u16be(v) { var b = Buffer.alloc(2); b.writeUInt16BE(v, 0); return b; }

function _encodeRecord(critical, type, body) {
  var hdr = Buffer.alloc(4);
  var typeField = type & 0x7fff;
  if (critical) typeField |= 0x8000;
  hdr.writeUInt16BE(typeField, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function _decodeRecords(buf) {
  var out = [];
  var off = 0;
  while (off + 4 <= buf.length) {
    var t = buf.readUInt16BE(off);
    var critical = (t & 0x8000) !== 0;
    var type = t & 0x7fff;
    var len = buf.readUInt16BE(off + 2);
    off += 4;
    if (off + len > buf.length) {
      throw new NtsError("NTS-KE record body length " + len + " exceeds buffer", "nts/bad-record");
    }
    var body = buf.slice(off, off + len);
    off += len;
    out.push({ critical: critical, type: type, body: body });
    if (type === REC_END) break;
  }
  return out;
}

function _aesEncryptBlock(key, block) {
  var c = nodeCrypto.createCipheriv("aes-" + (key.length * 8) + "-ecb", key, Buffer.alloc(0));
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

function _shl1(buf) {
  var out = Buffer.alloc(buf.length);
  var carry = 0;
  for (var i = buf.length - 1; i >= 0; i--) {
    var v = (buf[i] << 1) | carry;
    out[i] = v & 0xff;
    carry = (v >> 8) & 1;
  }
  return out;
}

function _xorBuf(a, b) {
  var out = Buffer.alloc(a.length);
  for (var i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function _cmacSubkeys(key) {
  var L = _aesEncryptBlock(key, Buffer.alloc(16, 0));
  var Rb = Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87]);
  var K1 = _shl1(L);
  if (L[0] & 0x80) K1 = _xorBuf(K1, Rb);
  var K2 = _shl1(K1);
  if (K1[0] & 0x80) K2 = _xorBuf(K2, Rb);
  return { K1: K1, K2: K2 };
}

function _cmac(key, message) {
  var subkeys = _cmacSubkeys(key);
  var n = Math.ceil(message.length / 16);
  if (n === 0) n = 1;
  var lastIsComplete = (message.length > 0) && (message.length % 16 === 0);
  var blocks = [];
  for (var i = 0; i < n - 1; i++) {
    blocks.push(message.slice(i * 16, i * 16 + 16));
  }
  var lastBlock;
  if (lastIsComplete) {
    lastBlock = _xorBuf(message.slice((n - 1) * 16, n * 16), subkeys.K1);
  } else {
    var rem = message.slice((n - 1) * 16);
    var padded = Buffer.alloc(16);
    rem.copy(padded);
    padded[rem.length] = 0x80;
    lastBlock = _xorBuf(padded, subkeys.K2);
  }
  blocks.push(lastBlock);
  var X = Buffer.alloc(16, 0);
  for (var b = 0; b < blocks.length; b++) {
    X = _aesEncryptBlock(key, _xorBuf(X, blocks[b]));
  }
  return X;
}

function _dbl(buf) {
  var Rb = Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87]);
  var shifted = _shl1(buf);
  if (buf[0] & 0x80) shifted = _xorBuf(shifted, Rb);
  return shifted;
}

function _s2v(K, strings, plaintext) {
  var D = _cmac(K, Buffer.alloc(16, 0));
  for (var i = 0; i < strings.length; i++) {
    D = _xorBuf(_dbl(D), _cmac(K, strings[i]));
  }
  var T;
  if (plaintext.length >= 16) {
    var head = plaintext.slice(0, plaintext.length - 16);
    var tail = plaintext.slice(plaintext.length - 16);
    var xored = _xorBuf(tail, D);
    T = Buffer.concat([head, xored]);
  } else {
    var padded = Buffer.alloc(16);
    plaintext.copy(padded);
    padded[plaintext.length] = 0x80;
    T = _xorBuf(_dbl(D), padded);
  }
  return _cmac(K, T);
}

function _aesCtr(key, iv, data) {
  var ivCopy = Buffer.from(iv);
  ivCopy[8]  &= 0x7f;
  ivCopy[12] &= 0x7f;
  var c = nodeCrypto.createCipheriv("aes-" + (key.length * 8) + "-ctr", key, ivCopy);
  return Buffer.concat([c.update(data), c.final()]);
}

function aesSivEncrypt(K, plaintext, associatedData) {
  if (K.length !== 32 && K.length !== 48 && K.length !== 64) {
    throw new NtsError("AES-SIV key must be 32/48/64 bytes, got " + K.length, "nts/bad-key");
  }
  var half = K.length / 2;
  var K1 = K.slice(0, half);
  var K2 = K.slice(half);
  var V = _s2v(K1, associatedData || [], plaintext);
  var ct = _aesCtr(K2, V, plaintext);
  return Buffer.concat([V, ct]);
}

function aesSivDecrypt(K, ciphertextWithIv, associatedData) {
  var half = K.length / 2;
  var K1 = K.slice(0, half);
  var K2 = K.slice(half);
  var V = ciphertextWithIv.slice(0, 16);
  var ct = ciphertextWithIv.slice(16);
  var pt = _aesCtr(K2, V, ct);
  var Vcheck = _s2v(K1, associatedData || [], pt);
  if (!nodeCrypto.timingSafeEqual(V, Vcheck)) {
    throw new NtsError("AES-SIV authentication failed", "nts/auth-failed");
  }
  return pt;
}

function _negotiateAead(preferList) {
  var defaultList = [AEAD_AES_SIV_CMAC_256, AEAD_CHACHA20_POLY1305];
  var list = (preferList && preferList.length > 0) ? preferList : defaultList;
  var body = Buffer.alloc(list.length * 2);
  for (var i = 0; i < list.length; i++) body.writeUInt16BE(list[i], i * 2);
  return body;
}

function _buildKeRequest(opts) {
  var aeadBody = _negotiateAead(opts.aead);
  var nextProto = _u16be(NTPV4_PROTOCOL_ID);
  var records = [
    _encodeRecord(true, REC_NEXT_PROTOCOL, nextProto),
    _encodeRecord(true, REC_AEAD_ALGORITHM, aeadBody),
    _encodeRecord(true, REC_END, Buffer.alloc(0)),
  ];
  return Buffer.concat(records);
}

function _exportKeys(socket, aeadId) {
  var label = "EXPORTER-network-time-security";
  var contextC2S = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x00]);
  var contextS2C = Buffer.from([0x00, 0x00, (aeadId >> 8) & 0xff, aeadId & 0xff, 0x01]);
  var keyLen = aeadId === AEAD_AES_SIV_CMAC_256 ? 32 : 32;
  var c2s = socket.exportKeyingMaterial(keyLen, label, contextC2S);
  var s2c = socket.exportKeyingMaterial(keyLen, label, contextS2C);
  return { c2s: c2s, s2c: s2c };
}

function performKeHandshake(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "servername", "aead", "ca", "timeoutMs"], "nts.performKeHandshake");
  if (typeof opts.host !== "string" || opts.host.length === 0) {
    throw new NtsError("nts.performKeHandshake: host required", "nts/bad-host");
  }
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(10);
  return new Promise(function (resolve, reject) {
    var settled = false;
    function done(err, result) {
      if (settled) return;
      settled = true;
      if (err) reject(err); else resolve(result);
    }
    var connectOpts = {
      host:           opts.host,
      port:           opts.port || NTS_KE_DEFAULT_PORT,
      servername:     opts.servername || opts.host,
      ALPNProtocols:  ["ntske/1"],
      minVersion:     "TLSv1.3",
      ecdhCurve:      C.TLS_GROUP_CURVE_STR,
    };
    if (opts.ca) connectOpts.ca = opts.ca;
    var sock = tls.connect(connectOpts);
    var timer = setTimeout(function () {
      try { sock.destroy(); } catch (_e) {}
      done(new NtsError("NTS-KE handshake timed out after " + timeoutMs + "ms", "nts/ke-timeout"));
    }, timeoutMs);
    timer.unref && timer.unref();
    sock.on("error", function (e) {
      clearTimeout(timer);
      done(new NtsError("NTS-KE socket error: " + e.message, "nts/ke-socket"));
    });
    sock.on("secureConnect", function () {
      if (sock.alpnProtocol !== "ntske/1") {
        clearTimeout(timer);
        try { sock.destroy(); } catch (_e) {}
        done(new NtsError("NTS-KE server did not negotiate ALPN 'ntske/1', got " + JSON.stringify(sock.alpnProtocol),
          "nts/bad-alpn"));
        return;
      }
      var req = _buildKeRequest(opts);
      sock.write(req);
    });
    var got = Buffer.alloc(0);
    var warnings = [];
    sock.on("data", function (chunk) {
      got = Buffer.concat([got, chunk]);
      try {
        var records = _decodeRecords(got);
        var endRec = records.find(function (r) { return r.type === REC_END; });
        if (!endRec) return;
        clearTimeout(timer);
        var errRec  = records.find(function (r) { return r.type === REC_ERROR; });
        if (errRec) {
          try { sock.destroy(); } catch (_e) {}
          done(new NtsError("NTS-KE server returned error code " + errRec.body.readUInt16BE(0), "nts/ke-error"));
          return;
        }
        var warnRecs = records.filter(function (r) { return r.type === REC_WARNING; });
        if (warnRecs.length > 0) {
          warnings = warnRecs.map(function (r) {
            return r.body.length >= 2 ? r.body.readUInt16BE(0) : null;
          }).filter(function (v) { return v != null; });
        }
        var aeadRec = records.find(function (r) { return r.type === REC_AEAD_ALGORITHM; });
        if (!aeadRec || aeadRec.body.length < 2) {
          try { sock.destroy(); } catch (_e) {}
          done(new NtsError("NTS-KE response missing AEAD algorithm", "nts/no-aead"));
          return;
        }
        var aeadId = aeadRec.body.readUInt16BE(0);
        if (aeadId !== AEAD_AES_SIV_CMAC_256 && aeadId !== AEAD_CHACHA20_POLY1305) {
          try { sock.destroy(); } catch (_e) {}
          done(new NtsError("NTS-KE server selected unsupported AEAD " + aeadId, "nts/unsupported-aead"));
          return;
        }
        var cookies = records.filter(function (r) { return r.type === REC_NEW_COOKIE; })
                              .map(function (r) { return r.body; });
        if (cookies.length === 0) {
          try { sock.destroy(); } catch (_e) {}
          done(new NtsError("NTS-KE response contained no cookies", "nts/no-cookies"));
          return;
        }
        var ntpServer = opts.host;
        var ntpPort   = NTPV4_DEFAULT_PORT;
        var srvRec = records.find(function (r) { return r.type === REC_NTPV4_SERVER; });
        if (srvRec) ntpServer = srvRec.body.toString("ascii");
        var portRec = records.find(function (r) { return r.type === REC_NTPV4_PORT; });
        if (portRec && portRec.body.length >= 2) ntpPort = portRec.body.readUInt16BE(0);
        var keys = _exportKeys(sock, aeadId);
        try { sock.end(); } catch (_e) {}
        done(null, {
          aeadId:    aeadId,
          c2sKey:    keys.c2s,
          s2cKey:    keys.s2c,
          cookies:   cookies,
          ntpServer: ntpServer,
          ntpPort:   ntpPort,
          warnings:  warnings,
        });
      } catch (e) {
        clearTimeout(timer);
        try { sock.destroy(); } catch (_e) {}
        done(e);
      }
    });
  });
}

function _encodeExtensionField(type, body) {
  var padLen = (4 - (body.length % 4)) % 4;
  var padded = padLen === 0 ? body : Buffer.concat([body, Buffer.alloc(padLen)]);
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(padded.length + 4, 2);
  return Buffer.concat([hdr, padded]);
}

function _aeadEncrypt(aeadId, key, nonce, plaintext, aad) {
  if (aeadId === AEAD_AES_SIV_CMAC_256) {
    var ad = aad ? [aad, nonce] : [nonce];
    return aesSivEncrypt(key, plaintext, ad);
  }
  if (aeadId === AEAD_CHACHA20_POLY1305) {
    var c = nodeCrypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    if (aad) c.setAAD(aad, { plaintextLength: plaintext.length });
    var ct = Buffer.concat([c.update(plaintext), c.final()]);
    var tag = c.getAuthTag();
    return Buffer.concat([ct, tag]);
  }
  throw new NtsError("aeadEncrypt: unsupported aead " + aeadId, "nts/aead-unsupported");
}

function _aeadDecrypt(aeadId, key, nonce, ciphertext, aad) {
  if (aeadId === AEAD_AES_SIV_CMAC_256) {
    var ad = aad ? [aad, nonce] : [nonce];
    return aesSivDecrypt(key, ciphertext, ad);
  }
  if (aeadId === AEAD_CHACHA20_POLY1305) {
    var ct = ciphertext.slice(0, ciphertext.length - 16);
    var tag = ciphertext.slice(ciphertext.length - 16);
    var d = nodeCrypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    if (aad) d.setAAD(aad, { plaintextLength: ct.length });
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  }
  throw new NtsError("aeadDecrypt: unsupported aead " + aeadId, "nts/aead-unsupported");
}

function _nonceForAead(aeadId) {
  if (aeadId === AEAD_AES_SIV_CMAC_256) return nodeCrypto.randomBytes(16);
  return nodeCrypto.randomBytes(12);
}

function querySingle(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "aeadId", "c2sKey", "s2cKey", "cookies", "timeoutMs"], "nts.querySingle");
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(5);
  if (!Array.isArray(opts.cookies) || opts.cookies.length === 0) {
    throw new NtsError("nts.querySingle: cookies array required", "nts/no-cookies");
  }
  return new Promise(function (resolve, reject) {
    var sock = dgram.createSocket("udp4");
    var settled = false;
    function done(err, result) {
      if (settled) return;
      settled = true;
      try { sock.close(); } catch (_e) {}
      if (err) reject(err); else resolve(result);
    }
    var unique = nodeCrypto.randomBytes(32);
    var cookie = opts.cookies[0];
    var packet = Buffer.alloc(48);
    packet[0] = 0x23;
    var ext1 = _encodeExtensionField(EXTENSION_UNIQUE_IDENTIFIER, unique);
    var ext2 = _encodeExtensionField(EXTENSION_NTS_COOKIE, cookie);
    var aeadHeader = Buffer.concat([packet, ext1, ext2]);
    var nonce = _nonceForAead(opts.aeadId);
    var encrypted = _aeadEncrypt(opts.aeadId, opts.c2sKey, nonce, Buffer.alloc(0), aeadHeader);
    var nonceLen = nonce.length;
    var ctLen = encrypted.length;
    var authBody = Buffer.alloc(4 + nonceLen + ctLen);
    authBody.writeUInt16BE(nonceLen, 0);
    authBody.writeUInt16BE(ctLen, 2);
    nonce.copy(authBody, 4);
    encrypted.copy(authBody, 4 + nonceLen);
    var ext3 = _encodeExtensionField(EXTENSION_NTS_AUTHENTICATOR_AND_ENC, authBody);
    var fullPacket = Buffer.concat([packet, ext1, ext2, ext3]);
    var sendTimeMs = Date.now();
    var timer = setTimeout(function () {
      done(new NtsError("NTS query timed out after " + timeoutMs + "ms", "nts/timeout"));
    }, timeoutMs);
    timer.unref && timer.unref();
    sock.on("error", function (e) {
      clearTimeout(timer);
      done(new NtsError("NTS udp error: " + e.message, "nts/socket"));
    });
    sock.on("message", function (msg) {
      clearTimeout(timer);
      var receiveTimeMs = Date.now();
      try {
        if (msg.length < 48) {
          done(new NtsError("NTS reply too short", "nts/bad-reply"));
          return;
        }
        var off = 48;
        var matchedUnique = false;
        while (off + 4 <= msg.length) {
          var t = msg.readUInt16BE(off);
          var len = msg.readUInt16BE(off + 2);
          if (len < 4 || off + len > msg.length) break;
          var body = msg.slice(off + 4, off + len);
          if (t === EXTENSION_UNIQUE_IDENTIFIER && nodeCrypto.timingSafeEqual(body.slice(0, 32), unique)) {
            matchedUnique = true;
          }
          off += len;
        }
        if (!matchedUnique) {
          done(new NtsError("NTS reply unique-identifier mismatch", "nts/unique-mismatch"));
          return;
        }
        var ntpSeconds  = msg.readUInt32BE(40);
        var ntpFraction = msg.readUInt32BE(44);
        var serverUnixSeconds = ntpSeconds - NTP_TO_UNIX_OFFSET_SECONDS;
        var fracMs = Math.round(ntpFraction / 0x100000000 * 1000);
        var serverTimeMs = serverUnixSeconds * 1000 + fracMs;
        var midpointMs = sendTimeMs + (receiveTimeMs - sendTimeMs) / 2;
        var driftMs = serverTimeMs - midpointMs;
        done(null, { driftMs: driftMs, serverTimeMs: serverTimeMs, server: opts.host, authenticated: true });
      } catch (e) {
        done(new NtsError("NTS reply processing failed: " + e.message, "nts/bad-reply"));
      }
    });
    sock.send(fullPacket, 0, fullPacket.length, opts.port || NTPV4_DEFAULT_PORT, opts.host, function (err) {
      if (err) {
        clearTimeout(timer);
        done(new NtsError("NTS send failed: " + err.message, "nts/send"));
      }
    });
  });
}

async function query(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "kePort", "ntpPort", "aead", "ca", "timeoutMs", "servername"], "nts.query");
  var ke = await performKeHandshake({
    host:       opts.host,
    port:       opts.kePort,
    servername: opts.servername,
    aead:       opts.aead,
    ca:         opts.ca,
    timeoutMs:  opts.timeoutMs,
  });
  var result = await querySingle({
    host:     ke.ntpServer,
    port:     opts.ntpPort || ke.ntpPort,
    aeadId:   ke.aeadId,
    c2sKey:   ke.c2sKey,
    s2cKey:   ke.s2cKey,
    cookies:  ke.cookies,
    timeoutMs: opts.timeoutMs,
  });
  return Object.assign({}, result, { aeadId: ke.aeadId, cookieCount: ke.cookies.length });
}

module.exports = {
  performKeHandshake:    performKeHandshake,
  querySingle:           querySingle,
  query:                 query,
  aesSivEncrypt:         aesSivEncrypt,
  aesSivDecrypt:         aesSivDecrypt,
  AEAD_AES_SIV_CMAC_256: AEAD_AES_SIV_CMAC_256,
  AEAD_CHACHA20_POLY1305: AEAD_CHACHA20_POLY1305,
  NtsError:              NtsError,
};
