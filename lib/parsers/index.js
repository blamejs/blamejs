"use strict";
/**
 * Multi-format safe parsers — apply the same security defaults blamejs's
 * b.json provides to other common data interchange formats.
 *
 * Currently shipped:
 *   xml  — RFC-compliant subset; XXE / DOCTYPE / billion-laughs blocked
 *           by default; depth + element + attribute count limits;
 *           numeric-character-ref bounds checked
 *   csv  — RFC 4180 parsing + writer with formula-injection prevention
 *           (cells starting with =/+/-/@/tab/CR get a single-quote
 *           prefix on stringify so Excel doesn't execute them)
 *
 * Not yet implemented (planned):
 *   yaml — safe-subset (JSON-shaped YAML); rejects tagged types,
 *           anchor cycles, !!python/object equivalents
 *   toml — TOML 1.0 parser with depth + size limits
 *   ini  — Windows .ini files (rare today; lower priority)
 *
 * Public API:
 *   parsers.xml.parse(input, opts?)              → object
 *   parsers.csv.parse(input, opts?)              → array
 *   parsers.csv.stringify(rows, opts?)           → string
 *
 * Error types: each parser exports its own *SafeError class with .code
 * matching the format (xml/..., csv/...).
 */
module.exports = {
  xml:  require("./xml-safe"),
  csv:  require("./csv-safe"),
};
