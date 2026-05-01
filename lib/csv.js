"use strict";
/**
 * csv — RFC 4180 parser + serializer.
 *
 * Public API:
 *
 *   b.csv.parse(text, opts?)        → { headers, rows }  (or { rows } if no header)
 *   b.csv.stringify(rows, opts?)    → string
 *
 * Opts (parse):
 *   delimiter:    ","   default
 *   header:       true  default — first row becomes column names; rows
 *                       are objects keyed by header
 *   maxBytes:     8 MiB default — refuses parse-bombs the same way
 *                       safeJson does
 *   onBadRow:     "throw" default | "skip" — what to do when a row has
 *                       a different column count than the header
 *
 * Opts (stringify):
 *   delimiter:    ","   default
 *   header:       true  default — emit a header row from object keys
 *   columns:      array of explicit column order (default: first row's keys)
 *   eol:          "\r\n" default — RFC 4180 mandates CRLF; some parsers
 *                       want LF. Operators choose.
 *
 * Format support:
 *   - Quoted fields with embedded commas, quotes ("" → "), newlines.
 *   - Optional BOM at file start (consumed silently if present).
 *   - Trailing newline tolerated (RFC 4180 says SHOULD; we tolerate).
 *
 * Throws CsvError (FrameworkError) on shape violations.
 */
var C = require("./constants");
var { defineClass } = require("./framework-error");

var CsvError = defineClass("CsvError", { alwaysPermanent: true });

var DEFAULT_MAX_BYTES = C.BYTES.mib(8);
var DEFAULT_DELIMITER = ",";
var DEFAULT_EOL       = "\r\n";

// ---- parse ----

function parse(text, opts) {
  opts = opts || {};
  if (typeof text !== "string" && !Buffer.isBuffer(text)) {
    throw new CsvError("csv/bad-input",
      "parse: input must be a string or Buffer, got " + typeof text);
  }
  var s = Buffer.isBuffer(text) ? text.toString("utf8") : text;
  var maxBytes = opts.maxBytes != null ? opts.maxBytes : DEFAULT_MAX_BYTES;
  if (Buffer.byteLength(s, "utf8") > maxBytes) {
    throw new CsvError("csv/too-large",
      "parse: input exceeds maxBytes (" + maxBytes + ")");
  }
  var delimiter = opts.delimiter || DEFAULT_DELIMITER;
  if (typeof delimiter !== "string" || delimiter.length !== 1) {
    throw new CsvError("csv/bad-delimiter",
      "parse: delimiter must be a single character, got " + JSON.stringify(delimiter));
  }
  if (delimiter === "\"" || delimiter === "\r" || delimiter === "\n") {
    throw new CsvError("csv/bad-delimiter",
      "parse: delimiter cannot be quote / CR / LF");
  }
  var hasHeader = opts.header !== false;
  var onBadRow = opts.onBadRow || "throw";
  if (onBadRow !== "throw" && onBadRow !== "skip") {
    throw new CsvError("csv/bad-opt",
      "parse: onBadRow must be 'throw' or 'skip'");
  }

  // Strip BOM if present.
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);

  var rows = [];
  var field = "";
  var row = [];
  var inQuotes = false;
  var i = 0;
  var len = s.length;
  while (i < len) {
    var c = s.charAt(i);
    if (inQuotes) {
      if (c === "\"") {
        if (i + 1 < len && s.charAt(i + 1) === "\"") {
          field += "\"";    // escaped quote
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === "\"") {
      // Quote at the start of a field (or anywhere — treat as start of
      // quoted run). RFC 4180 says quoted fields begin with a quote;
      // fields that contain a quote not at the start are technically
      // malformed but we tolerate by appending literally.
      if (field.length === 0) {
        inQuotes = true;
        i++;
        continue;
      }
      field += "\"";
      i++;
      continue;
    }
    if (c === delimiter) {
      row.push(field);
      field = "";
      i++;
      continue;
    }
    if (c === "\r") {
      // CRLF or bare CR — treat both as row terminator.
      row.push(field);
      rows.push(row);
      field = "";
      row = [];
      if (i + 1 < len && s.charAt(i + 1) === "\n") i += 2;
      else i++;
      continue;
    }
    if (c === "\n") {
      row.push(field);
      rows.push(row);
      field = "";
      row = [];
      i++;
      continue;
    }
    field += c;
    i++;
  }
  // Flush any trailing field/row (no trailing newline case)
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  if (!hasHeader) {
    return { rows: rows };
  }
  if (rows.length === 0) {
    return { headers: [], rows: [] };
  }
  var headers = rows[0];
  var out = [];
  for (var r = 1; r < rows.length; r++) {
    var current = rows[r];
    if (current.length === 1 && current[0] === "") continue;   // skip blank lines
    if (current.length !== headers.length) {
      if (onBadRow === "skip") continue;
      throw new CsvError("csv/row-length-mismatch",
        "parse: row " + r + " has " + current.length + " columns, expected " + headers.length);
    }
    var obj = {};
    for (var k = 0; k < headers.length; k++) obj[headers[k]] = current[k];
    out.push(obj);
  }
  return { headers: headers, rows: out };
}

// ---- stringify ----

function stringify(rows, opts) {
  opts = opts || {};
  if (!Array.isArray(rows)) {
    throw new CsvError("csv/bad-input",
      "stringify: rows must be an array");
  }
  var delimiter = opts.delimiter || DEFAULT_DELIMITER;
  var eol       = opts.eol || DEFAULT_EOL;
  var hasHeader = opts.header !== false;
  if (rows.length === 0) return "";

  var columns;
  if (Array.isArray(opts.columns)) {
    columns = opts.columns.slice();
  } else if (Array.isArray(rows[0])) {
    // Array-of-arrays input — no headers to derive; emit as-is.
    columns = null;
  } else if (rows[0] && typeof rows[0] === "object") {
    columns = Object.keys(rows[0]);
  } else {
    throw new CsvError("csv/bad-input",
      "stringify: rows[0] must be an object or array");
  }

  var lines = [];
  if (hasHeader && columns) lines.push(columns.map(_quoteCell).join(delimiter));

  for (var r = 0; r < rows.length; r++) {
    var row = rows[r];
    var cells;
    if (Array.isArray(row)) {
      cells = row.map(_quoteCell);
    } else if (row && typeof row === "object") {
      cells = (columns || Object.keys(row)).map(function (col) {
        return _quoteCell(row[col]);
      });
    } else {
      throw new CsvError("csv/bad-input",
        "stringify: rows[" + r + "] must be an object or array");
    }
    lines.push(cells.join(delimiter));
  }
  return lines.join(eol) + eol;
}

function _quoteCell(value) {
  if (value === null || value === undefined) return "";
  var s = typeof value === "string" ? value : String(value);
  if (s.indexOf("\"") !== -1 || s.indexOf(",") !== -1 ||
      s.indexOf("\r") !== -1 || s.indexOf("\n") !== -1) {
    return "\"" + s.replace(/"/g, "\"\"") + "\"";
  }
  return s;
}

module.exports = {
  parse:     parse,
  stringify: stringify,
  CsvError:  CsvError,
};
