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
 *   toml — TOML 1.0 parsing with depth + size limits;
 *           prototype-pollution rejection on dotted-key path segments;
 *           strict same-key redefinition (silent overwrite would mask
 *           config errors operators DO want surfaced); offset
 *           date-times decoded as JS Date, local date-time/date/time
 *           preserved as ISO strings (no implicit offset assumption);
 *           integers > MAX_SAFE_INTEGER rejected so 64-bit values
 *           must be encoded as quoted strings
 *
 * Not yet implemented (planned):
 *   yaml — safe-subset (JSON-shaped YAML); rejects tagged types,
 *           anchor cycles, !!python/object equivalents
 *   env  — .env file loader with size cap + schema validation;
 *           refuses to expand $VAR references; refuses to silently
 *           overwrite existing process.env values unless explicitly
 *           opted in. Dev-tooling — production secrets should still
 *           come through the operator's secrets-management; this is
 *           the local-development convenience.
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
  toml: require("./toml-safe"),
};
