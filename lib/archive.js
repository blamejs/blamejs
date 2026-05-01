"use strict";
/**
 * archive — ZIP creation. Operator-data-export shape ("download my
 * data as a zip"), log archives, plain-zip exports for users.
 *
 *   var archive = b.archive.zip();
 *   archive.addFile("readme.txt",     "Hello\n");
 *   archive.addFile("data/users.csv", csvBytes, { method: "deflate" });
 *   archive.addFile("avatars/me.png", pngBuf,   { method: "store" });   // already-compressed
 *   var zipBytes = archive.toBuffer();
 *
 *   // OR write directly to disk:
 *   archive.writeTo("/tmp/export.zip");
 *
 * Format support:
 *   - Stored (no compression — for already-compressed inputs like
 *     PNG / JPEG / mp4)
 *   - Deflate via node:zlib's deflateRawSync (default for everything else)
 *   - File names with / are honored — directory entries are implicit;
 *     extractors create the directory structure on demand
 *   - UTF-8 file names (sets the EFS bit per APPNOTE 6.3.4)
 *   - Modification time defaults to "now"; operators override per file
 *
 * v1 scope cuts (deferred):
 *   - ZIP64 (>4 GiB archives, >65535 files) — operators with that
 *     scale bring their own
 *   - Encryption — `b.crypto.encryptPacked` produces a sealed bundle
 *     for the operator's encryption-at-rest needs; ZIP-native
 *     password encryption is broken-by-design
 *   - Streaming write (toStream) — toBuffer() is enough for the
 *     "download my data" shape; operators streaming gigabytes
 *     have a different toolset
 *   - Reading / extraction — write-only for now
 */
var zlib = require("node:zlib");
var fs   = require("node:fs");
var nodeCrypto = require("node:crypto");
var { defineClass } = require("./framework-error");

var ArchiveError = defineClass("ArchiveError", { alwaysPermanent: true });

// ZIP signatures
var SIG_LFH = 0x04034b50;   // local file header
var SIG_CFH = 0x02014b50;   // central directory file header
var SIG_EOCD = 0x06054b50;  // end of central directory

// Compression methods
var METHOD_STORE   = 0;
var METHOD_DEFLATE = 8;

// CRC-32 — IEEE 802.3 polynomial. node:crypto has no native CRC32, so
// we vendor the standard table-driven implementation.
var CRC32_TABLE = (function () {
  var t = new Uint32Array(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
})();

function _crc32(buf) {
  var crc = 0xffffffff;
  for (var i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// MS-DOS date/time encoding — APPNOTE 4.4.6
function _msdosDateTime(date) {
  var d = date instanceof Date ? date : new Date(date);
  if (isNaN(d.getTime())) d = new Date();
  var dosTime = ((d.getHours() & 0x1f) << 11) |
                ((d.getMinutes() & 0x3f) << 5) |
                ((Math.floor(d.getSeconds() / 2)) & 0x1f);
  var dosDate = (((d.getFullYear() - 1980) & 0x7f) << 9) |
                (((d.getMonth() + 1) & 0xf) << 5) |
                (d.getDate() & 0x1f);
  return { time: dosTime, date: dosDate };
}

function zip() {
  var entries = [];

  function addFile(name, content, opts) {
    if (typeof name !== "string" || name.length === 0) {
      throw new ArchiveError("archive/bad-name", "addFile: name must be a non-empty string");
    }
    if (name.indexOf("\0") !== -1) {
      throw new ArchiveError("archive/bad-name", "addFile: name contains null byte");
    }
    // No path traversal — relative paths only, no leading slash, no ".." segments.
    var normalized = name.replace(/\\/g, "/").replace(/^\/+/, "");
    var segs = normalized.split("/");
    for (var si = 0; si < segs.length; si++) {
      if (segs[si] === "..") {
        throw new ArchiveError("archive/bad-name", "addFile: name contains '..' segment");
      }
    }
    var bodyBuf;
    if (Buffer.isBuffer(content)) bodyBuf = content;
    else if (typeof content === "string") bodyBuf = Buffer.from(content, "utf8");
    else throw new ArchiveError("archive/bad-content",
      "addFile: content must be a Buffer or string, got " + typeof content);

    opts = opts || {};
    var method = opts.method === "store" ? METHOD_STORE : METHOD_DEFLATE;
    var mtime = opts.mtime instanceof Date ? opts.mtime : new Date();

    var crc = _crc32(bodyBuf);
    var stored = bodyBuf;
    if (method === METHOD_DEFLATE) {
      stored = zlib.deflateRawSync(bodyBuf);
      // If deflate didn't shrink it (small/already-compressed inputs),
      // fall back to STORE to save the operator a few bytes.
      if (stored.length >= bodyBuf.length) {
        stored = bodyBuf;
        method = METHOD_STORE;
      }
    }

    entries.push({
      name:           normalized,
      method:         method,
      mtime:          mtime,
      crc:            crc,
      stored:         stored,
      uncompressedSize: bodyBuf.length,
    });
  }

  function _buildLocalFileHeader(entry) {
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    var hdr = Buffer.alloc(30);
    hdr.writeUInt32LE(SIG_LFH, 0);
    hdr.writeUInt16LE(20, 4);         // version needed
    hdr.writeUInt16LE(0x0800, 6);     // flags: bit 11 = UTF-8 name
    hdr.writeUInt16LE(entry.method, 8);
    hdr.writeUInt16LE(dt.time, 10);
    hdr.writeUInt16LE(dt.date, 12);
    hdr.writeUInt32LE(entry.crc, 14);
    hdr.writeUInt32LE(entry.stored.length, 18);
    hdr.writeUInt32LE(entry.uncompressedSize, 22);
    hdr.writeUInt16LE(nameBuf.length, 26);
    hdr.writeUInt16LE(0, 28);         // extra field length
    return Buffer.concat([hdr, nameBuf]);
  }

  function _buildCentralDirectoryEntry(entry, lfhOffset) {
    var nameBuf = Buffer.from(entry.name, "utf8");
    var dt = _msdosDateTime(entry.mtime);
    var hdr = Buffer.alloc(46);
    hdr.writeUInt32LE(SIG_CFH, 0);
    hdr.writeUInt16LE(0x033f, 4);     // version made by (UNIX | 6.3)
    hdr.writeUInt16LE(20, 6);         // version needed
    hdr.writeUInt16LE(0x0800, 8);     // flags: bit 11 = UTF-8
    hdr.writeUInt16LE(entry.method, 10);
    hdr.writeUInt16LE(dt.time, 12);
    hdr.writeUInt16LE(dt.date, 14);
    hdr.writeUInt32LE(entry.crc, 16);
    hdr.writeUInt32LE(entry.stored.length, 20);
    hdr.writeUInt32LE(entry.uncompressedSize, 24);
    hdr.writeUInt16LE(nameBuf.length, 28);
    hdr.writeUInt16LE(0, 30);         // extra field length
    hdr.writeUInt16LE(0, 32);         // file comment length
    hdr.writeUInt16LE(0, 34);         // disk number start
    hdr.writeUInt16LE(0, 36);         // internal file attributes
    hdr.writeUInt32LE(0, 38);         // external file attributes
    hdr.writeUInt32LE(lfhOffset, 42);
    return Buffer.concat([hdr, nameBuf]);
  }

  function toBuffer() {
    if (entries.length > 65535) {
      throw new ArchiveError("archive/too-many-entries",
        "ZIP archive cannot contain more than 65535 entries (ZIP64 unsupported in v1)");
    }
    var pieces = [];
    var offsets = [];
    var totalLocalBytes = 0;
    for (var i = 0; i < entries.length; i++) {
      offsets.push(totalLocalBytes);
      var lfh = _buildLocalFileHeader(entries[i]);
      pieces.push(lfh);
      pieces.push(entries[i].stored);
      totalLocalBytes += lfh.length + entries[i].stored.length;
    }
    var cdStart = totalLocalBytes;
    var cdSize = 0;
    for (var j = 0; j < entries.length; j++) {
      var cdh = _buildCentralDirectoryEntry(entries[j], offsets[j]);
      pieces.push(cdh);
      cdSize += cdh.length;
    }
    // End of Central Directory
    var eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(SIG_EOCD, 0);
    eocd.writeUInt16LE(0, 4);                    // disk number
    eocd.writeUInt16LE(0, 6);                    // disk where CD starts
    eocd.writeUInt16LE(entries.length, 8);       // entries on this disk
    eocd.writeUInt16LE(entries.length, 10);      // total entries
    eocd.writeUInt32LE(cdSize, 12);              // size of central directory
    eocd.writeUInt32LE(cdStart, 16);             // offset of central directory
    eocd.writeUInt16LE(0, 20);                   // comment length
    pieces.push(eocd);
    return Buffer.concat(pieces);
  }

  function writeTo(filepath) {
    var buf = toBuffer();
    fs.writeFileSync(filepath, buf);
    return buf.length;
  }

  function digest() {
    // SHA-256 of the produced archive bytes — useful for operator-side
    // integrity logging on exported bundles. Not vendor-locked to any
    // particular hash; SHA-256 is universally recognized for content
    // addressing.
    return nodeCrypto.createHash("sha256").update(toBuffer()).digest("hex");
  }

  return {
    addFile:    addFile,
    toBuffer:   toBuffer,
    writeTo:    writeTo,
    digest:     digest,
    get entryCount() { return entries.length; },
  };
}

module.exports = {
  zip:           zip,
  ArchiveError:  ArchiveError,
  // Test-only export — operators don't call this; it's here for unit-testing
  // the CRC implementation against known vectors.
  _crc32ForTest: _crc32,
};
