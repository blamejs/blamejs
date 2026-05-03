"use strict";
/**
 * csv — RFC 4180 parser + serializer with operator-friendly defaults.
 *
 *   var rows = b.csv.parse(text);
 *     // header row by default — returns array of objects keyed by header
 *     // [ { name: "alice", age: "30" }, ... ]
 *
 *   var arrays = b.csv.parse(text, { header: false });
 *     // returns array of arrays
 *
 *   var out = b.csv.stringify(rows);
 *     // RFC 4180 + Excel-formula-injection prevention by default
 *
 * Defaults:
 *   parse:
 *     header:        true              first row is column names
 *     delimiter:     ","               single byte; "\t" / ";" supported
 *     quote:         '"'
 *     trim:          false             cell whitespace preserved
 *     maxBytes:      16 MiB
 *     maxRows:       1,000,000
 *     maxFieldBytes: 1 MiB
 *     onBadRow:      "throw"           "skip" tolerates short/long rows
 *
 *   stringify:
 *     header:                  true (or array of explicit columns)
 *     delimiter:               ","
 *     quote:                   '"'
 *     eol:                     "\r\n"  RFC 4180; "\n" via opt
 *     alwaysQuote:             false   only quote when needed
 *     preventFormulaInjection: true    prefix '=' / '+' / '-' / '@' / TAB / CR
 *                                       cells with "'" so Excel doesn't
 *                                       execute them when the CSV is opened
 *     formulaPrefixChars:      ["=","+","-","@","\t","\r"]
 *
 * SECURITY: stringify defends against CSV-injection (Excel/Sheets execute
 * cells starting with "=" / "+" / "-" / "@" / TAB / CR as formulas).
 * Operator-controlled cells stay safe; user-supplied cells get the leading
 * single-quote so the formula engine sees a literal string.
 *
 * Throws CsvError (FrameworkError, permanent) on shape violations.
 */
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var CsvError = defineClass("CsvError", { alwaysPermanent: true });

var DEFAULTS_PARSE = {
  header:        true,
  delimiter:     ",",
  quote:         "\"",
  trim:          false,
  maxBytes:      C.BYTES.mib(16),
  maxRows:       1000000,
  maxFieldBytes: C.BYTES.mib(1),
  onBadRow:      "throw",
};

var DEFAULTS_STRINGIFY = {
  header:                  true,
  delimiter:               ",",
  quote:                   "\"",
  eol:                     "\r\n",
  alwaysQuote:             false,
  preventFormulaInjection: true,
  formulaPrefixChars:      ["=", "+", "-", "@", "\t", "\r"],
  columns:                 null,
};

function _validateDelim(name, value) {
  if (typeof value !== "string" || value.length !== 1) {
    throw new CsvError("csv/bad-delimiter",
      name + " must be a single character, got " + JSON.stringify(value));
  }
  if (value === "\r" || value === "\n") {
    throw new CsvError("csv/bad-delimiter",
      name + " cannot be CR or LF");
  }
}

// ---- parse ----

function parse(input, opts) {
  opts = Object.assign({}, DEFAULTS_PARSE, opts || {});
  // maxBytes via shared lib/numeric-bounds — Infinity / NaN bypass the
  // body cap and let a hostile multi-megabyte CSV through unbounded.
  if (!numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new CsvError("csv/bad-opt",
      "csv.parse: maxBytes must be a positive finite integer; got " +
        numericBounds.shape(opts.maxBytes));
  }

  var s;
  if (typeof input === "string") s = input;
  else if (Buffer.isBuffer(input)) s = input.toString("utf8");
  else if (input instanceof Uint8Array) s = Buffer.from(input).toString("utf8");
  else {
    throw new CsvError("csv/bad-input",
      "parse: input must be string, Buffer, or Uint8Array, got " + typeof input);
  }
  if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  if (Buffer.byteLength(s, "utf8") > opts.maxBytes) {
    throw new CsvError("csv/too-large",
      "parse: input exceeds maxBytes (" + opts.maxBytes + ")");
  }

  _validateDelim("delimiter", opts.delimiter);
  _validateDelim("quote",     opts.quote);
  if (opts.delimiter === opts.quote) {
    throw new CsvError("csv/bad-delimiter",
      "delimiter and quote must differ");
  }
  if (opts.onBadRow !== "throw" && opts.onBadRow !== "skip") {
    throw new CsvError("csv/bad-opt",
      "onBadRow must be 'throw' or 'skip'");
  }

  var len = s.length;
  var pos = 0;
  var rows = [];
  var row = [];
  var field = "";
  var inQuote = false;

  function pushField() {
    if (Buffer.byteLength(field, "utf8") > opts.maxFieldBytes) {
      throw new CsvError("csv/field-too-large",
        "field exceeds maxFieldBytes at row " + (rows.length + 1));
    }
    row.push(opts.trim ? field.trim() : field);
    field = "";
  }
  function pushRow() {
    pushField();
    rows.push(row);
    if (rows.length > opts.maxRows) {
      throw new CsvError("csv/too-many-rows",
        "row count exceeds maxRows (" + opts.maxRows + ")");
    }
    row = [];
  }

  while (pos < len) {
    var ch = s.charAt(pos);
    if (inQuote) {
      if (ch === opts.quote) {
        if (pos + 1 < len && s.charAt(pos + 1) === opts.quote) {
          field += opts.quote;
          pos += 2;
          continue;
        }
        inQuote = false;
        pos += 1;
        continue;
      }
      field += ch;
      pos += 1;
    } else {
      if (ch === opts.delimiter) {
        pushField();
        pos += 1;
      } else if (ch === "\r") {
        pushRow();
        pos += 1;
        if (pos < len && s.charAt(pos) === "\n") pos += 1;
      } else if (ch === "\n") {
        pushRow();
        pos += 1;
      } else if (ch === opts.quote && field === "") {
        inQuote = true;
        pos += 1;
      } else {
        field += ch;
        pos += 1;
      }
    }
  }
  if (inQuote) {
    throw new CsvError("csv/unterminated-quote",
      "unterminated quoted field");
  }
  if (field.length > 0 || row.length > 0) pushRow();

  if (!opts.header) return rows;
  if (rows.length === 0) return [];

  var header = rows[0];
  var out = [];
  for (var r = 1; r < rows.length; r++) {
    var rec = rows[r];
    if (rec.length !== header.length) {
      if (opts.onBadRow === "skip") continue;
      throw new CsvError("csv/row-length-mismatch",
        "row " + r + " has " + rec.length + " fields, header has " + header.length);
    }
    var obj = {};
    for (var i = 0; i < header.length; i++) obj[header[i]] = rec[i];
    out.push(obj);
  }
  return out;
}

// ---- stringify ----

function stringify(rows, opts) {
  opts = Object.assign({}, DEFAULTS_STRINGIFY, opts || {});
  if (!Array.isArray(rows)) {
    throw new CsvError("csv/bad-input",
      "stringify: rows must be an array, got " + typeof rows);
  }
  _validateDelim("delimiter", opts.delimiter);
  _validateDelim("quote",     opts.quote);
  if (opts.delimiter === opts.quote) {
    throw new CsvError("csv/bad-delimiter",
      "delimiter and quote must differ");
  }
  if (opts.eol !== "\r\n" && opts.eol !== "\n") {
    throw new CsvError("csv/bad-opt",
      "eol must be '\\r\\n' or '\\n'");
  }
  if (rows.length === 0) return "";

  var first = rows[0];
  var asObjects;
  var header;
  if (Array.isArray(first)) {
    asObjects = false;
    header = Array.isArray(opts.columns) ? opts.columns : null;
  } else if (first !== null && typeof first === "object") {
    asObjects = true;
    header = Array.isArray(opts.columns) ? opts.columns : Object.keys(first);
  } else {
    throw new CsvError("csv/bad-input",
      "stringify: rows must be arrays or plain objects");
  }

  var prefixSet = Object.create(null);
  for (var pi = 0; pi < opts.formulaPrefixChars.length; pi++) {
    prefixSet[opts.formulaPrefixChars[pi]] = true;
  }

  function escapeCell(value) {
    var str = value == null ? "" : String(value);
    if (opts.preventFormulaInjection && str.length > 0 && prefixSet[str.charAt(0)]) {
      str = "'" + str;
    }
    var needsQuote = opts.alwaysQuote ||
      str.indexOf(opts.delimiter) !== -1 ||
      str.indexOf(opts.quote) !== -1 ||
      str.indexOf("\n") !== -1 ||
      str.indexOf("\r") !== -1;
    if (needsQuote) {
      str = opts.quote + str.split(opts.quote).join(opts.quote + opts.quote) + opts.quote;
    }
    return str;
  }

  var out = [];
  if (opts.header && header) {
    out.push(header.map(escapeCell).join(opts.delimiter));
  }
  for (var i = 0; i < rows.length; i++) {
    var rec = rows[i];
    var cells;
    if (asObjects) {
      cells = header.map(function (k) { return escapeCell(rec[k]); });
    } else {
      cells = rec.map(escapeCell);
    }
    out.push(cells.join(opts.delimiter));
  }
  return out.join(opts.eol);
}

module.exports = {
  parse:               parse,
  stringify:           stringify,
  CsvError:            CsvError,
  DEFAULTS_PARSE:      DEFAULTS_PARSE,
  DEFAULTS_STRINGIFY:  DEFAULTS_STRINGIFY,
};
