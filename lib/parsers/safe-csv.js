"use strict";
/**
 * Security-focused CSV parser + writer.
 *
 * RFC 4180 compliant parsing + the operator-friendly defaults that the
 * RFC doesn't address:
 *
 *   - Size + row-count + field-length limits (DoS prevention)
 *   - BOM stripping
 *   - Configurable delimiter (',' default; '\t' for TSV; ';' for European)
 *   - Configurable quote char
 *   - CRLF / LF / CR line endings all accepted
 *
 * SECURITY: writer prevents CSV/Excel formula injection. Excel and other
 * spreadsheet apps execute cells starting with '=', '+', '-', '@', or
 * tab/CR characters. By default the writer prefixes such cells with a
 * single quote so the formula doesn't execute when the file is opened.
 * Toggle with { preventFormulaInjection: false } for true RFC 4180 output.
 *
 * Public API:
 *   csv.parse(input, opts?)          → array of arrays | array of objects
 *   csv.stringify(rows, opts?)       → string (RFC 4180 + injection-safe)
 *   csv.SafeCsvError                 → error class
 *
 * Defaults (parse):
 *   maxBytes:        16 MiB
 *   maxRows:         1,000,000
 *   maxFieldBytes:   1 MiB
 *   delimiter:       ','
 *   quote:           '"'
 *   header:          true   (first row is column names; rows returned as objects)
 *   trim:            false  (don't trim cell whitespace by default)
 */

var C = require("../constants");
var safeBuffer = require("../safe-buffer");
var { FrameworkError } = require("../framework-error");

class SafeCsvError extends FrameworkError {
  constructor(message, code, position) {
    super(message);
    this.name = "SafeCsvError";
    this.code = code || "csv/invalid";
    this.position = position || null;
    this.isSafeCsvError = true;
  }
}

var DEFAULTS_PARSE = {
  maxBytes:      C.BYTES.mib(16),
  maxRows:       1000000,
  maxFieldBytes: C.BYTES.mib(1),
  delimiter:     ",",
  quote:         '"',
  header:        true,
  trim:          false,
};

var DEFAULTS_STRINGIFY = {
  delimiter:                ",",
  quote:                    '"',
  preventFormulaInjection:  true,
  formulaPrefixChars:       ["=", "+", "-", "@", "\t", "\r"],
  always_quote:             false,   // quote every field; default only quotes when needed
  newline:                  "\r\n",  // RFC 4180
  header:                   null,    // explicit array; null → derive from first object's keys
};

// ---- parse ----

function parse(input, opts) {
  opts = Object.assign({}, DEFAULTS_PARSE, opts || {});

  input = safeBuffer.normalizeText(input, {
    maxBytes:   opts.maxBytes,
    errorClass: SafeCsvError,
    typeCode:   "csv/wrong-input-type",
    sizeCode:   "csv/too-large",
  });

  var len = input.length;
  var pos = 0;
  var rows = [];
  var row = [];
  var field = "";
  var inQuote = false;

  function pushField() {
    if (Buffer.byteLength(field, "utf8") > opts.maxFieldBytes) {
      throw new SafeCsvError("field exceeds maxFieldBytes at row " + (rows.length + 1), "csv/field-too-large");
    }
    row.push(opts.trim ? field.trim() : field);
    field = "";
  }
  function pushRow() {
    pushField();
    rows.push(row);
    if (rows.length > opts.maxRows) {
      throw new SafeCsvError("row count exceeds maxRows", "csv/too-many-rows");
    }
    row = [];
  }

  while (pos < len) {
    var ch = input.charAt(pos);
    if (inQuote) {
      if (ch === opts.quote) {
        // Possible escaped quote (double-quote inside quoted field)
        if (pos + 1 < len && input.charAt(pos + 1) === opts.quote) {
          field += opts.quote;
          pos += 2;
          continue;
        }
        // End of quoted field
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
        // CR or CRLF — both end the row
        pushRow();
        pos += 1;
        if (pos < len && input.charAt(pos) === "\n") pos += 1;
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
  if (inQuote) throw new SafeCsvError("unterminated quoted field", "csv/unterminated-quote");
  // Final row (no trailing newline)
  if (field.length > 0 || row.length > 0) {
    pushRow();
  }

  if (opts.header) {
    if (rows.length === 0) return [];
    var header = rows[0];
    return rows.slice(1).map(function (r) {
      var obj = {};
      for (var i = 0; i < header.length; i++) obj[header[i]] = r[i] !== undefined ? r[i] : null;
      return obj;
    });
  }
  return rows;
}

// ---- stringify ----

function stringify(rows, opts) {
  opts = Object.assign({}, DEFAULTS_STRINGIFY, opts || {});
  if (!Array.isArray(rows)) {
    throw new SafeCsvError("stringify expects an array of rows", "csv/wrong-input-type");
  }
  if (rows.length === 0) return "";

  // Determine header + row shape
  var header;
  var isObjectRows = false;
  if (Array.isArray(rows[0])) {
    isObjectRows = false;
    header = opts.header || null;
  } else if (typeof rows[0] === "object" && rows[0] !== null) {
    isObjectRows = true;
    header = opts.header || Object.keys(rows[0]);
  } else {
    throw new SafeCsvError("rows must be arrays or objects", "csv/wrong-input-type");
  }

  function escapeCell(value) {
    var s = value == null ? "" : String(value);
    if (opts.preventFormulaInjection && s.length > 0) {
      var first = s.charAt(0);
      if (opts.formulaPrefixChars.indexOf(first) !== -1) {
        s = "'" + s;   // Excel-safe prefix
      }
    }
    var needsQuote = opts.always_quote ||
      s.indexOf(opts.delimiter) !== -1 ||
      s.indexOf(opts.quote) !== -1 ||
      s.indexOf("\n") !== -1 ||
      s.indexOf("\r") !== -1;
    if (needsQuote) {
      s = opts.quote + s.split(opts.quote).join(opts.quote + opts.quote) + opts.quote;
    }
    return s;
  }

  var out = [];
  if (header) {
    out.push(header.map(escapeCell).join(opts.delimiter));
  }
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var cells;
    if (isObjectRows) {
      cells = header.map(function (k) { return escapeCell(r[k]); });
    } else {
      cells = r.map(escapeCell);
    }
    out.push(cells.join(opts.delimiter));
  }
  return out.join(opts.newline);
}

module.exports = {
  parse:                parse,
  stringify:            stringify,
  SafeCsvError:         SafeCsvError,
  DEFAULTS_PARSE:       DEFAULTS_PARSE,
  DEFAULTS_STRINGIFY:   DEFAULTS_STRINGIFY,
};
