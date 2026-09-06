// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Token-aware shape-matcher for codebase-patterns detectors.
 *
 * The framework's codebase-patterns gate has historically been regex-only,
 * which is trivially bypassed by renaming variables, adding parens, or
 * splitting across lines (see the v0.11.3 PR-108 audit findings). This
 * module is the bounded-grammar shape-matcher PR-2 introduces: it
 * tokenizes the source, tracks paren / brace / bracket depth + string
 * state + comment state, and exposes primitives for the detector
 * shapes the audit named:
 *
 *   - findCalls(source, calleeRegex)
 *       → every call whose callee identifier-chain matches the regex,
 *         regardless of whitespace / parens / line splits.
 *   - findEnclosingTry(source, callPos)
 *       → does the call sit inside `try { ... }` ? Used by the rule §5
 *         drop-silent audit-emit detector.
 *   - findEnclosingFn(source, callPos)
 *       → start/end positions of the containing function body.
 *   - findStatementBefore(source, callPos)
 *       → the previous statement (same brace depth, prior `;` or `{`).
 *   - findStatementAfter(source, callPos)
 *       → next sibling statement at the same depth.
 *   - aliasesOf(source, identChain)
 *       → every local var name that was assigned from this identifier
 *         chain anywhere in `source`. Catches the v0.11.3 audit's
 *         "alias bypass" class (`var emit = audit.emit; emit(...)`).
 *
 * Not a full ECMAScript parser. The framework code is CommonJS + var +
 * no JSX + no TypeScript by design, so the lexer is small (~200 lines).
 * Primitives are conservative — ambiguous shapes (regex-vs-division,
 * escaped template-literal substitutions across line boundaries) yield
 * `null` rather than guessing.
 *
 * Lives in test/helpers/, never ships in the npm tarball — `test/` is
 * absent from package.json `files:` allowlist (verified at PR-2 build).
 */

// ---- Lexer ----

var TOK_IDENT      = "ident";
var TOK_NUMBER     = "number";
var TOK_STRING     = "string";
var TOK_TEMPLATE   = "template";
var TOK_REGEX      = "regex";
var TOK_PUNCT      = "punct";
var TOK_COMMENT    = "comment";
var TOK_WS         = "ws";
var TOK_KEYWORD    = "keyword";

var KEYWORDS = {
  "var": 1, "let": 1, "const": 1, "function": 1, "return": 1, "if": 1,
  "else": 1, "for": 1, "while": 1, "do": 1, "switch": 1, "case": 1,
  "default": 1, "break": 1, "continue": 1, "try": 1, "catch": 1,
  "finally": 1, "throw": 1, "new": 1, "delete": 1, "typeof": 1,
  "instanceof": 1, "in": 1, "of": 1, "void": 1, "this": 1, "null": 1,
  "true": 1, "false": 1, "undefined": 1, "async": 1, "await": 1,
  "yield": 1, "class": 1, "extends": 1, "super": 1, "import": 1,
  "export": 1, "from": 1, "as": 1,
  // `debugger` is a complete statement, so a pattern may begin on the line
  // after it. Left out of this table it tokenized as an identifier, and an
  // identifier divides, so the pattern following one was read as division and
  // never emitted. The sibling lexer in this file already listed it.
  "debugger": 1,
};

// Punctuation characters that can begin a token. Multi-char operators
// (===, !==, &&, ||, ??, =>, etc.) are recognised greedily in tokenize.
var PUNCT_CHARS = "{}()[];,.<>!=+-*/%&|^~?:";

// Whether a token at position `i-1` (last non-ws/comment) suggests the
// next `/` opens a regex literal versus a division operator. This is
// the classic JS ambiguity; we use the standard rule: regex follows
// any context that demands an expression — operators, keywords like
// `return` / `typeof` / `new`, or the start of input.
// Does the text hold a line terminator? Compared by code point rather than
// against a character class, so the four ECMAScript terminators are named
// here without any of them appearing in this file.
var LINE_TERMINATOR_CODES = [0x0A, 0x0D, 0x2028, 0x2029];

// Space, tab, the two ASCII line breaks and the two Unicode ones, by code.
function _isSpaceCode(cc) {
  return cc === 0x20 || cc === 0x09 || cc === 0x0A || cc === 0x0D ||
         cc === 0x2028 || cc === 0x2029;
}
function _hasLineTerminator(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (LINE_TERMINATOR_CODES.indexOf(text.charCodeAt(i)) !== -1) return true;
  }
  return false;
}

// The token, as the single-character form the brace classifier reads. That
// classifier takes the last significant TEXT rather than a token, so a value
// token is handed the character its kind is spelled with.
// The significant token before the given one, skipping whitespace and
// comments. Used where one token alone does not say what a word is: a name
// after `class` is a name whatever it is spelled like.
function _significantBefore(tokens, tok) {
  var seenIt = false;
  for (var i = tokens.length - 1; i >= 0; i -= 1) {
    var t = tokens[i];
    if (t.type === TOK_WS || t.type === TOK_COMMENT) continue;
    if (!seenIt) { seenIt = (t === tok); continue; }
    return t;
  }
  return null;
}

// Was there a line terminator between the last significant token and here?
// Reads back over the whitespace and comments the caller skipped.
function _lineBreakBeforeEnd(tokens) {
  for (var i = tokens.length - 1; i >= 0; i -= 1) {
    var t = tokens[i];
    if (t.type !== TOK_WS && t.type !== TOK_COMMENT) return false;
    if (_hasLineTerminator(t.value)) return true;
  }
  return false;
}

// The keywords ECMAScript forbids a line terminator after: one there ends the
// statement, so what follows starts a new one. `yield` and a newline leave the
// brace on the next line opening a BLOCK rather than an object.
var _RESTRICTED_PRODUCTIONS = {
  "return": 1, "throw": 1, "yield": 1, "break": 1, "continue": 1,
};

function _lastSigText(tok) {
  if (!tok) return "";
  if (tok.type === TOK_NUMBER) return "0";
  if (tok.type === TOK_STRING) return "\"";
  if (tok.type === TOK_TEMPLATE) return "`";
  if (tok.type === TOK_REGEX) return "0";                 // a value, so a brace after it opens an object
  // A colon either separates a property from its value or closes a ternary,
  // and both are followed by a value; or it ends a label or a `case`, and
  // those are followed by a STATEMENT. Handing the raw colon to the brace
  // classifier read `label: {}` as an object.
  if (tok.value === ":" && tok.colonIsValue !== true) return _STATEMENT_POSITION;
  // A keyword written as a property name is a VALUE, not the keyword: the
  // brace after `class X extends B.default {}` opens a class body, and handing
  // the classifier the word `default` answered for a keyword nobody wrote.
  if (tok.isProperty === true) return "0";
  // `debugger` is a complete statement, so the brace after it opens a BLOCK.
  // It sits in the regex-leading set, which the brace classifier reads as "a
  // value may follow", and that is the one place the two questions differ.
  if (tok.value === "debugger") return _STATEMENT_POSITION;
  return tok.value;
}

function _slashIsRegex(prevSignificant) {
  if (!prevSignificant) return true;
  if (prevSignificant.type === TOK_IDENT) {
    // A word after `break` or `continue` is the LABEL those take, and nothing
    // divides a label, so a slash after one opens a pattern the way it does
    // after the bare keyword.
    if (prevSignificant.isBreakLabel === true) return true;
    // After an identifier we don't know whether it's a variable name
    // (division) or an unparenthesised expression-tail. Be conservative:
    // identifiers preceded only by `return`, `typeof`, etc. resolve via
    // keyword check; bare identifiers we treat as division.
    return false;
  }
  if (prevSignificant.type === TOK_NUMBER ||
      prevSignificant.type === TOK_STRING ||
      prevSignificant.type === TOK_TEMPLATE ||
      prevSignificant.type === TOK_REGEX) return false;
  if (prevSignificant.type === TOK_KEYWORD) {
    // A keyword in property position is a value, so a slash after it divides.
    if (prevSignificant.isProperty === true) return false;
    var kw = prevSignificant.value;
    // After these keywords a `/` is part of a regex literal.
    // `else` and `do` are followed by the statement they govern, which may be
    // unbraced and may begin with a pattern: `else /re/.test(s);`.
    // `break` and `continue` take a label and nothing else, so a slash after
    // one is never division; with the semicolon left to insertion, the next
    // statement can begin with a pattern on the following line.
    if (kw === "return" || kw === "typeof" || kw === "throw" ||
        kw === "new" || kw === "delete" || kw === "void" ||
        kw === "instanceof" || kw === "in" || kw === "of" ||
        kw === "case" || kw === "yield" || kw === "await" ||
        kw === "else" || kw === "do" ||
        kw === "debugger" ||
        kw === "break" || kw === "continue") return true;
    return false;
  }
  if (prevSignificant.type === TOK_PUNCT) {
    // After most punctuation a `/` is a regex. Exceptions: `)` and `]`
    // and `}` which can close an expression and thus a following `/`
    // is division. (Object-literal `}` is statement-end and would be a
    // regex — but the bounded grammar we care about uses semicolons.)
    var p = prevSignificant.value;
    // The paren that closed a control-flow header is followed by a statement,
    // and a statement may begin with a pattern: `if (ok) /re/.test(s);`.
    if (p === ")") return prevSignificant.closedControlHeader === true;
    if (p === "]") return false;
    // A POSTFIX `++` or `--` ends an expression, so the slash after it is
    // division: `x++ / 2`. Reading it as a pattern opener swallows the rest of
    // the line and consumes the opening slash of the next real one. A PREFIX
    // one is followed by its operand, which may begin with a pattern.
    if (p === "++" || p === "--") return prevSignificant.isPostfix !== true;
    // A `}` that closed an OBJECT closed an expression, so the slash after it
    // divides: `var n = {} / 2`. One that closed a block ended a statement, and
    // a statement may begin with a pattern. Which it is cannot be read off the
    // brace, so it is decided at the matching `{`, the way the comment stripper
    // in this file already decides it.
    if (p === "}") {
      // The body of a function or class EXPRESSION closes a value too, so a
      // slash after it divides just as it does after an object.
      if (prevSignificant.closedValueBody === true) return false;
      return prevSignificant.closedObject !== true;
    }
    return true;
  }
  return true;
}

function tokenize(source) {
  var tokens = [];
  var i = 0;
  var n = source.length;
  var prevSig = null;
  var parenStack = [];
  var braceStack = [];
  // Per open brace: does it open the body of a function or class EXPRESSION,
  // whose closing brace is therefore followed by division rather than by a
  // statement? Kept beside braceStack so the two are pushed and popped together.
  var valueBodyStack = [];
  var frames = [{ ternary: 0, isObject: false }];
  while (i < n) {
    var ch = source.charAt(i);
    var cc = source.charCodeAt(i);

    // Whitespace. The two Unicode line terminators count: a token that skips
    // them as unknown leaves no whitespace between the statements they
    // separate, so a reader asking whether a line break came between finds
    // none and reads two statements as one.
    if (_isSpaceCode(cc)) {
      var ws = i;
      while (i < n && _isSpaceCode(source.charCodeAt(i))) {
        i += 1;
      }
      tokens.push({ type: TOK_WS, value: source.slice(ws, i), start: ws, end: i });
      continue;
    }

    // Line comment
    if (ch === "/" && source.charAt(i + 1) === "/") {
      var lc = i;
      // Every line terminator ends a line comment, not only LF. Stopping at LF
      // alone swallowed the rest of a CR-terminated file as one comment, and
      // whatever followed, including a pattern, was never seen.
      while (i < n && LINE_TERMINATOR_CODES.indexOf(source.charCodeAt(i)) === -1) i += 1;
      tokens.push({ type: TOK_COMMENT, value: source.slice(lc, i), start: lc, end: i });
      continue;
    }

    // Block comment
    if (ch === "/" && source.charAt(i + 1) === "*") {
      var bc = i; i += 2;
      while (i < n && !(source.charAt(i) === "*" && source.charAt(i + 1) === "/")) i += 1;
      if (i < n) i += 2;
      tokens.push({ type: TOK_COMMENT, value: source.slice(bc, i), start: bc, end: i });
      continue;
    }

    // String literal — single or double quote
    if (ch === "'" || ch === '"') {
      var sQuote = ch; var ss = i; i += 1;
      while (i < n) {
        var c3 = source.charAt(i);
        if (c3 === "\\") { i += 2; continue; }
        if (c3 === sQuote) { i += 1; break; }
        if (c3 === "\n") break;                                                    // unterminated — caller deals
        i += 1;
      }
      var stok = { type: TOK_STRING, value: source.slice(ss, i), start: ss, end: i };
      tokens.push(stok); prevSig = stok;
      continue;
    }

    // Template literal — backtick. Where a substitution ends is found by
    // counting braces, which is wrong about a brace written inside a string, a
    // comment, a nested template or a character class.
    //
    // Lexing the substitution instead answers those correctly and is the
    // change this file does NOT make. What sits between `${` and its `}` is
    // code, so a lexer is the right instrument, but this lexer is incomplete
    // in ways that are known and being worked through one at a time, and
    // reading a substitution with it turns each remaining gap from one
    // mis-read token into the loss of every pattern after the template: a
    // scan that runs past the closing brace ends the template at some later
    // backtick, and nothing about that is detectable from the result. Counting
    // is wrong about a narrower thing and wrong locally. The framework holds
    // no substitution that either reads incorrectly.
    if (ch === "`") {
      var ts = i;
      var tEnd = _templateEnd(source, ts);
      i = tEnd === -1 ? n : tEnd;
      var ttok = { type: TOK_TEMPLATE, value: source.slice(ts, i), start: ts, end: i };
      tokens.push(ttok); prevSig = ttok;
      continue;
    }

    // Regex literal — only if grammar position allows
    if (ch === "/" && _slashIsRegex(prevSig)) {
      var rs = i; i += 1;
      var inClass = false;
      while (i < n) {
        var c5 = source.charAt(i);
        if (c5 === "\\") { i += 2; continue; }
        if (c5 === "[") { inClass = true; i += 1; continue; }
        if (c5 === "]") { inClass = false; i += 1; continue; }
        if (c5 === "/" && !inClass) { i += 1; break; }
        if (c5 === "\n") break;                                                    // unterminated
        i += 1;
      }
      // Trailing flags
      // `v` is a flag Node accepts, and stopping before it ends the token
      // early: the flag is then read as an identifier, and a caller that
      // rebuilds the pattern from this token builds one without it.
      while (i < n && /[gimsuydv]/.test(source.charAt(i))) i += 1;
      var rtok = { type: TOK_REGEX, value: source.slice(rs, i), start: rs, end: i };
      tokens.push(rtok); prevSig = rtok;
      continue;
    }

    // Number literal — simple. Includes hex, octal, binary, decimal.
    if (cc >= 48 && cc <= 57) {                                                    // 0..9
      var ns = i; i += 1;
      while (i < n && /[0-9a-fA-FxXbBoOeE._n+-]/.test(source.charAt(i))) {
        // Stop at a `-`/`+` that isn't part of an exponent
        var nc = source.charAt(i);
        if ((nc === "+" || nc === "-") && !/[eE]/.test(source.charAt(i - 1))) break;
        i += 1;
      }
      var ntok = { type: TOK_NUMBER, value: source.slice(ns, i), start: ns, end: i };
      tokens.push(ntok); prevSig = ntok;
      continue;
    }

    // Identifier / keyword
    if (/[A-Za-z_$]/.test(ch)) {
      var is = i; i += 1;
      while (i < n && /[A-Za-z0-9_$]/.test(source.charAt(i))) i += 1;
      var idVal = source.slice(is, i);
      var idType = KEYWORDS[idVal] ? TOK_KEYWORD : TOK_IDENT;
      var itok = { type: idType, value: idVal, start: is, end: i };
      // Every keyword is also a legal property name, and one in that position
      // is a value rather than a keyword: `obj.return / 2` and `obj.else / 2`
      // both divide. Recorded here, where the preceding token is known.
      if (prevSig !== null && prevSig.type === TOK_PUNCT &&
          (prevSig.value === "." || prevSig.value === "?.")) {
        itok.isProperty = true;
      }
      // The word after `break` or `continue` is the label they jump to, but
      // only on the same line: these forbid a line terminator before the
      // label, so one there ends the statement and the word starts the next.
      if (prevSig !== null && prevSig.type === TOK_KEYWORD &&
          (prevSig.value === "break" || prevSig.value === "continue") &&
          !_lineBreakBeforeEnd(tokens)) {
        itok.isBreakLabel = true;
      }
      tokens.push(itok); prevSig = itok;
      continue;
    }

    // Punctuation (multi-char operators recognised greedily)
    if (PUNCT_CHARS.indexOf(ch) !== -1) {
      var ps = i;
      // Greedy: 3-char first (===, !==, ...), then 2-char (==, !=, &&,
      // ||, ??, =>, **, <<, >>, ...), then 1-char.
      var three = source.slice(i, i + 3);
      var two = source.slice(i, i + 2);
      if (three === "===" || three === "!==" || three === "..." ||
          three === ">>>" || three === "**=" || three === "<<=" ||
          three === ">>=" || three === "&&=" || three === "||=" ||
          three === "??=") {
        i += 3;
      } else if (two === "==" || two === "!=" || two === "<=" || two === ">=" ||
                 two === "&&" || two === "||" || two === "??" || two === "=>" ||
                 two === "**" || two === "<<" || two === ">>" ||
                 two === "+=" || two === "-=" || two === "*=" || two === "/=" ||
                 two === "%=" || two === "&=" || two === "|=" || two === "^=" ||
                 two === "++" || two === "--" || two === "?.") {
        i += 2;
      } else {
        i += 1;
      }
      var ptok = { type: TOK_PUNCT, value: source.slice(ps, i), start: ps, end: i };
      // `++` and `--` are POSTFIX only when there was something to operate on,
      // no line terminator came between (one ends the statement, so the
      // operator belongs to the next), and the paren before it did not close a
      // control-flow header (`if (ok) ++x` is a statement, not an operand).
      // A prefix one is followed by its operand, which may begin with a
      // pattern, and the two forms decide the next slash differently.
      // Whether a `}` closed an object or a block is decided at the matching
      // `{`, by the same classifier the comment stripper uses. Two answers to
      // one structural question drift, and this one had drifted: every `}` read
      // as a statement end, so `var n = {} / 2` had its division read as a
      // pattern opener, which then swallowed the next real one.
      // A ternary lives inside the nearest enclosing group, so each `(` and
      // `{` opens a frame that counts its own `?`. Without that, the `:` of a
      // ternary written inside an object is taken for a property colon.
      if (ptok.value === "(") {
        frames.push({ ternary: 0, isObject: false });
      } else if (ptok.value === ")") {
        if (frames.length > 1) frames.pop();
      } else if (ptok.value === "{") {
        // A restricted-production keyword with a line terminator after it has
        // ended its statement, so the brace opens a block whatever the keyword
        // would otherwise imply.
        var braceLastSig = _lastSigText(prevSig);
        if (prevSig !== null && prevSig.type === TOK_KEYWORD &&
            _RESTRICTED_PRODUCTIONS[prevSig.value] === 1 &&
            _lineBreakBeforeEnd(tokens)) {
          braceLastSig = _STATEMENT_POSITION;
        }
        // A word right after `class` or `function` is that thing's NAME, not
        // the word it is spelled like: `class of {}` names a class `of`, and
        // the brace opens its body. Reading the name as the keyword `of` made
        // the body an object.
        var beforePrev = _significantBefore(tokens, prevSig);
        if (beforePrev !== null && beforePrev.type === TOK_KEYWORD &&
            (beforePrev.value === "class" || beforePrev.value === "function")) {
          braceLastSig = _STATEMENT_POSITION;
        }
        var opensObject = _braceOpensObject(braceLastSig);
        // A function or class EXPRESSION produces a value, so the brace closing
        // its body is followed by division: `var x = function () {} / 2`. A
        // DECLARATION's body ends a statement, and a statement may begin with a
        // pattern. The brace cannot say which, so it is settled here at the
        // `{`, the way the paren case is settled at the matching `(`. Reading
        // every function body as a block made the slash after one open a
        // pattern, which then ran to the opener of the next real one.
        // Expression position is the same question `{` already asks about an
        // object, so it is asked with the same function: at the start of input,
        // after `;`, after `{`, or after a keyword that introduces a block, the
        // word begins a statement and the body is a declaration's.
        var kwTok = _governingFunctionOrClass(tokens);
        var beforeKw = kwTok === null ? null : _significantBefore(tokens, kwTok);
        var kwLastSig = _lastSigText(beforeKw);
        // A restricted-production keyword with a line terminator after it has
        // ended its statement, so what follows begins a new one and the word is
        // a declaration: `return` on its own line, then `function g(){}`, whose
        // brace closes a statement and not a value.
        if (beforeKw !== null && beforeKw.type === TOK_KEYWORD &&
            _RESTRICTED_PRODUCTIONS[beforeKw.value] === 1 &&
            _lineBreakBackFrom(source, kwTok.start)) {
          kwLastSig = _STATEMENT_POSITION;
        }
        // `export` and `default` introduce a DECLARATION, so the body they
        // carry ends a statement. `default` otherwise reads as a word after
        // which an expression follows, which is true of a `switch` label and
        // not of `export default function f(){}`.
        if (beforeKw !== null && beforeKw.type === TOK_KEYWORD &&
            (beforeKw.value === "export" || beforeKw.value === "default")) {
          kwLastSig = _STATEMENT_POSITION;
        }
        valueBodyStack.push(kwTok !== null && _braceOpensObject(kwLastSig));
        braceStack.push(opensObject);
        frames.push({ ternary: 0, isObject: opensObject });
      } else if (ptok.value === "}") {
        ptok.closedObject = braceStack.pop() === true;
        ptok.closedValueBody = valueBodyStack.pop() === true;
        if (frames.length > 1) frames.pop();
      } else if (ptok.value === "?") {
        frames[frames.length - 1].ternary += 1;
      } else if (ptok.value === ":") {
        var frame = frames[frames.length - 1];
        if (frame.ternary > 0) { frame.ternary -= 1; ptok.colonIsValue = true; }
        else ptok.colonIsValue = frame.isObject === true;
      }
      if (ptok.value === "++" || ptok.value === "--") {
        var operandBefore = prevSig !== null &&
          (prevSig.type === TOK_IDENT || prevSig.type === TOK_NUMBER ||
           prevSig.type === TOK_STRING || prevSig.type === TOK_TEMPLATE ||
           prevSig.type === TOK_REGEX ||
           (prevSig.type === TOK_PUNCT &&
            (prevSig.value === "]" ||
             (prevSig.value === ")" && prevSig.closedControlHeader !== true))));
        ptok.isPostfix = operandBefore && !_lineBreakBeforeEnd(tokens);
      }
      // Whether a `)` allows a pattern after it is decided at the matching
      // `(`: the paren that closes `if (ok)` is followed by the statement it
      // governs, which may begin with one, while the paren that closes
      // `(a + b)` is followed by division. The comment stripper in this file
      // already decides it that way, and reading it two ways is how the two
      // answers drift.
      if (ptok.value === "(") {
        // `for await (` puts a transparent word between the keyword and the
        // paren, so the word before is read through the same way the comment
        // stripper reads it. Looking only at the token next to the paren
        // classifies `for await` as a call.
        var head = prevSig;
        if (head !== null && (head.type === TOK_KEYWORD || head.type === TOK_IDENT) &&
            _TRANSPARENT_WORDS[head.value] === 1) {
          for (var bk = tokens.length - 1; bk >= 0; bk -= 1) {
            var bt = tokens[bk];
            if (bt.type === TOK_WS || bt.type === TOK_COMMENT) continue;
            if ((bt.type === TOK_KEYWORD || bt.type === TOK_IDENT) &&
                _TRANSPARENT_WORDS[bt.value] === 1) continue;
            head = bt;
            break;
          }
        }
        // A control keyword is also a legal property name, and `obj.if(x) / 2`
        // divides. Property position is recorded on the token itself.
        parenStack.push(head !== null && head.isProperty !== true &&
                        (head.type === TOK_KEYWORD || head.type === TOK_IDENT) &&
                        _CONTROL_HEADER_KEYWORDS[head.value] === 1);
      } else if (ptok.value === ")") {
        ptok.closedControlHeader = parenStack.pop() === true;
      }
      tokens.push(ptok); prevSig = ptok;
      continue;
    }

    // Unknown — skip one char to avoid infinite loop
    i += 1;
  }
  return tokens;
}

// Filter to significant tokens (drop whitespace + comments) but keep the
// original `start`/`end` positions so callers can map back to source.
function significantTokens(tokens) {
  var out = [];
  for (var i = 0; i < tokens.length; i += 1) {
    if (tokens[i].type !== TOK_WS && tokens[i].type !== TOK_COMMENT) out.push(tokens[i]);
  }
  return out;
}

// Reverse-lookup: from source position → significant-tokens index.
function _sigIdxBeforePos(sig, pos) {
  for (var i = sig.length - 1; i >= 0; i -= 1) {
    if (sig[i].end <= pos) return i;
  }
  return -1;
}

// ---- Primitive: findCalls ----
//
// Match every call of the form `<head>(...)` where `<head>` is an
// identifier chain (`foo`, `foo.bar`, `foo.bar.baz`, `foo["bar"]`).
// `calleeRegex` is matched against the joined chain (e.g. `audit.emit`).
//
// Returns an array of `{ chain, openParen, closeParen, head: {start,end},
//                        call: {start,end} }`.
function findCalls(source, calleeRegex) {
  var tokens = tokenize(source);
  var sig = significantTokens(tokens);
  var out = [];
  for (var i = 0; i < sig.length; i += 1) {
    if (sig[i].type !== TOK_PUNCT || sig[i].value !== "(") continue;
    // Walk back to collect the identifier-chain head.
    var chain = [];
    var j = i - 1;
    var headEnd = sig[i].start;
    while (j >= 0) {
      var t = sig[j];
      if (t.type === TOK_IDENT) {
        chain.unshift(t.value);
        // Continue past a preceding `.`
        if (j > 0 && sig[j - 1].type === TOK_PUNCT && sig[j - 1].value === ".") {
          j -= 2; continue;
        }
        break;
      }
      // Bracket access: ["foo"] — pop the string token if present
      if (t.type === TOK_PUNCT && t.value === "]") {
        // walk to matching [
        var bdepth = 1; var k = j - 1; var member = null;
        while (k >= 0 && bdepth > 0) {
          if (sig[k].type === TOK_PUNCT && sig[k].value === "]") bdepth += 1;
          else if (sig[k].type === TOK_PUNCT && sig[k].value === "[") bdepth -= 1;
          if (bdepth === 1 && sig[k].type === TOK_STRING) {
            member = sig[k].value.slice(1, -1);
          }
          k -= 1;
        }
        if (member !== null) chain.unshift(member);
        // continue past optional `.` if any (rare with bracket access)
        j = k;
        if (j >= 0 && sig[j].type === TOK_PUNCT && sig[j].value === ".") {
          j -= 1; continue;
        }
        continue;
      }
      break;
    }
    if (chain.length === 0) continue;
    var joined = chain.join(".");
    if (!calleeRegex.test(joined)) continue;
    // Find matching `)`
    var pdepth = 1; var p = i + 1;
    while (p < sig.length && pdepth > 0) {
      if (sig[p].type === TOK_PUNCT) {
        if (sig[p].value === "(") pdepth += 1;
        else if (sig[p].value === ")") pdepth -= 1;
      }
      p += 1;
    }
    if (pdepth !== 0) continue;                                                     // unterminated
    var closeIdx = p - 1;
    var headStartIdx = j + 1;
    if (headStartIdx < 0) headStartIdx = 0;
    out.push({
      chain:      joined,
      head:       { start: sig[headStartIdx].start, end: headEnd },
      openParen:  sig[i].start,
      closeParen: sig[closeIdx].end,
      call:       { start: sig[headStartIdx].start, end: sig[closeIdx].end },
    });
  }
  return out;
}

// ---- Primitive: findEnclosingTry / findEnclosingFn ----
//
// Both walk a brace-depth stack backward from `pos` to find the
// nearest `<keyword> {` opener whose matching `}` is past `pos`.
function _findEnclosing(source, pos, keywordRegex) {
  var tokens = tokenize(source);
  var sig = significantTokens(tokens);
  // Build per-token depth (running brace depth at token start).
  var depth = 0;
  var depths = new Array(sig.length);
  for (var i = 0; i < sig.length; i += 1) {
    depths[i] = depth;
    if (sig[i].type === TOK_PUNCT) {
      if (sig[i].value === "{") depth += 1;
      else if (sig[i].value === "}") depth -= 1;
    }
  }
  // Find sig-index immediately containing pos.
  var atIdx = -1;
  for (var k = 0; k < sig.length; k += 1) {
    if (sig[k].start <= pos && pos < sig[k].end) { atIdx = k; break; }
    if (sig[k].start > pos) { atIdx = k - 1; break; }
  }
  if (atIdx < 0) atIdx = sig.length - 1;
  var atDepth = depths[atIdx];
  // Walk backward looking for `<keyword>` whose immediately following
  // `{` (or `( ... ) {` for function) opens a block that contains pos.
  for (var b = atIdx - 1; b >= 0; b -= 1) {
    if (sig[b].type !== TOK_KEYWORD) continue;
    if (!keywordRegex.test(sig[b].value)) continue;
    // Walk forward from b to find the `{` that opens this block.
    var braceStart = -1;
    for (var f = b + 1; f < sig.length; f += 1) {
      if (sig[f].type === TOK_PUNCT && sig[f].value === "{") {
        braceStart = f; break;
      }
      // No braces allowed for try/catch/finally — they must be
      // immediately followed by `{`. For function we may pass through
      // `(...)` and a return-type — keep walking.
    }
    if (braceStart === -1) continue;
    // depth at the brace = depths[braceStart]; depth inside = +1
    var braceDepth = depths[braceStart] + 1;
    if (braceDepth !== atDepth) continue;                                            // not this one
    // Find matching `}`
    var bd = 1; var fi = braceStart + 1;
    while (fi < sig.length && bd > 0) {
      if (sig[fi].type === TOK_PUNCT) {
        if (sig[fi].value === "{") bd += 1;
        else if (sig[fi].value === "}") bd -= 1;
      }
      fi += 1;
    }
    if (bd !== 0) continue;
    var closeBrace = sig[fi - 1].end;
    if (sig[braceStart].start < pos && pos < closeBrace) {
      return {
        keyword:    sig[b].value,
        keywordPos: sig[b].start,
        bodyStart:  sig[braceStart].start,
        bodyEnd:    closeBrace,
      };
    }
  }
  return null;
}

function findEnclosingTry(source, pos) {
  return _findEnclosing(source, pos, /^(try)$/);
}

function findEnclosingFn(source, pos) {
  return _findEnclosing(source, pos, /^(function)$/);
}

// ---- Primitive: aliasesOf ----
//
// Scan source for every `var <name> = <chain>;` / `const ...` /
// `let ...` / `<name> = <chain>;` where `<chain>` matches `chainRegex`.
// Returns the set of `<name>`s. Used to detect aliased call sites.
function aliasesOf(source, chainRegex) {
  var tokens = tokenize(source);
  var sig = significantTokens(tokens);
  var out = {};
  for (var i = 0; i < sig.length - 3; i += 1) {
    // Pattern: [var|const|let|identifier] IDENT = <chain>...
    var head = sig[i];
    var nameIdx = i + 1;
    var eqIdx = i + 2;
    if (head.type === TOK_KEYWORD && (head.value === "var" || head.value === "const" || head.value === "let")) {
      // var X = ...
    } else if (head.type === TOK_IDENT && sig[i + 1] && sig[i + 1].type === TOK_PUNCT && sig[i + 1].value === "=") {
      // X = ...  (bare assignment)
      nameIdx = i;
      eqIdx = i + 1;
    } else {
      continue;
    }
    if (!sig[nameIdx] || sig[nameIdx].type !== TOK_IDENT) continue;
    if (!sig[eqIdx] || sig[eqIdx].type !== TOK_PUNCT || sig[eqIdx].value !== "=") continue;
    // Collect identifier chain after `=`. Stop at `;`, `,`, `)`, end-of-line newline.
    var chain = [];
    var j = eqIdx + 1;
    while (j < sig.length) {
      var t = sig[j];
      if (t.type === TOK_IDENT) {
        chain.push(t.value);
        if (sig[j + 1] && sig[j + 1].type === TOK_PUNCT && sig[j + 1].value === ".") {
          j += 2; continue;
        }
        break;
      }
      break;
    }
    if (chain.length < 2) continue;                                                 // need a chain (foo.bar at minimum)
    var joined = chain.join(".");
    if (chainRegex.test(joined)) out[sig[nameIdx].value] = joined;
  }
  return out;
}

// ---- Primitive: positionToLineCol ----

function positionToLineCol(source, pos) {
  var line = 1, col = 1;
  for (var i = 0; i < pos && i < source.length; i += 1) {
    if (source.charCodeAt(i) === 10) { line += 1; col = 1; }
    else col += 1;
  }
  return { line: line, col: col };
}

// ---- Comment stripping ----
//
// Remove comments, for checks that assert a construct IS PRESENT.
//
// A presence check reading a commented-out occurrence concludes the construct
// is there and stays silent, which is the exact state it exists to catch. So
// it is worth tracking state: block comments spanning lines, string literals
// so a `/*` inside one is not a comment opener, and regex literals so a `//`
// inside one does not delete the rest of the line.
//
// Newlines inside block comments are preserved so line numbers don't shift.
// Strings and template TEXT are preserved deliberately — over-stripping is the
// other failure mode, and it reports files that are fine, which is how a check
// earns an allowlist entry and stops being read.
//
// Both directions are pinned by testCommentStripHelper in
// test/layer-0-primitives/codebase-patterns.test.js.

// Can a `/` at this point open a REGEX, or does it divide? Decided by what
// came before it — the same ambiguity `_slashIsRegex` resolves above, asked of
// a character rather than a token. After a VALUE (an identifier, a number, a
// closing `)` `]` `}`, a string, a template) a slash divides; after an
// operator, an opening bracket, a comma, a semicolon or nothing, it opens a
// regex. The keywords are the case a character-wise rule cannot see: `return`
// and `typeof` end in a letter but demand an expression.
// Two groups, and the division is what each keyword leaves BEHIND it:
//
//   - an operand is still owed, so an expression follows — `return`, `typeof`,
//     `throw`, `new`, `delete`, `void`, `instanceof`, `in`, `of`, `case`,
//     `yield`, `await`;
//   - the statement is finished, so a new one follows — `break`, `continue`,
//     `debugger`, `do`, `else`, `try`, `finally`, `default`.
//
// Everything else reserved is either a value (`this`, `super`, `true`,
// `false`, `null`) or cannot be followed by a slash in valid source at all
// (`var`, `const`, `let`, `function`, `class`, `if`, `while`, `for`, `switch`,
// `catch`, `with`, `import`, `export`, `extends`, `static`, `enum`, `async`,
// `get`, `set`) — and the keyword sweep in codebase-patterns.test.js walks the
// whole reserved list against the parse invariant rather than trusting this
// comment, because `break` was missing from it and deleted a file's tail.
var _REGEX_LEADING_KEYWORDS = {
  "return": 1, "typeof": 1, "throw": 1, "new": 1, "delete": 1, "void": 1,
  "instanceof": 1, "in": 1, "of": 1, "case": 1, "yield": 1, "await": 1,
  "do": 1, "else": 1, "break": 1, "continue": 1, "debugger": 1,
  "try": 1, "finally": 1, "default": 1, "extends": 1,
};

// A consumed regex literal is a value, and the single character it ends with —
// `/` — is also the division operator, so the two cannot share a marker.
// `@` never begins a real token, which keeps this distinct from anything the
// character path can produce.
var _VALUE_REGEX = "@regex";

// Likewise a consumed numeric literal. Read character by character, the last
// one is not reliably a digit — `1.` ends in a dot, `0x1F` in a letter — and
// each spelling would need its own entry in the value list. Consumed whole and
// reported as one marker, the whole family answers at once.
var _VALUE_NUMBER = "@num";

// A word that followed a dot. It is a PROPERTY NAME, whatever it spells, so the
// member expression it completes is a value and a slash after it divides. The
// word alone cannot say this: `o.default / 2` and a `default` ending a statement
// are the same characters, and reading the first as the second opened a pattern
// that ran to the first slash of the next `//`, leaving that comment behind as
// code. Twenty-one reserved words read that way.
var _VALUE_MEMBER = "@member";

// Where the next STATEMENT begins. A pattern may start here, and so may a
// block — the two questions have different answers at the same spot, which is
// why the position is recorded rather than approximated by the character that
// happened to precede it. Reported by the `)` that closed a control-flow
// header and by the `}` that closed a block.
var _STATEMENT_POSITION = "@stmt";

// A `)` usually ends an expression, so a slash after it divides — `(a + b) / c`.
// The exception is the `)` that closes a control-flow HEADER: the statement it
// governs follows, and a statement may begin with a pattern. `if (ok)
// /[/*]/.test(x)` is valid, and reading its slash as division put the `/*`
// inside the character class back in play as a comment opener, which deletes
// everything to the next `*/`.
//
// Which case a `)` is cannot be decided from the `)`. It is decided at the
// matching `(`, by the word in front of it, so the openers are tracked on a
// per-frame stack and the answer read back when the paren closes.
var _CONTROL_HEADER_KEYWORDS = {
  "if": 1, "while": 1, "for": 1, "with": 1,
};

// Does a slash at this point DIVIDE? Every token that can end an expression is
// listed; anything else leaves an expression position open, where a slash
// starts a pattern.
//
// The test is anchored. Unanchored, a multi-character token fell through to
// "not a value" — `i++ / count` read the division as a pattern opener and
// consumed into the trailing comment, leaving it in the source the presence
// gates read, which is the state this stripper exists to prevent.
function _slashDivides(lastSig) {
  if (lastSig === "") return false;                      // start of input
  // The two markers are compared by name. Spelling one of them inside the
  // pattern below would put the same value in two places, and a rename would
  // then leave the pattern quietly matching nothing.
  if (lastSig === _VALUE_REGEX) return true;             // a pattern is a value
  if (lastSig === _VALUE_NUMBER) return true;            // so is a number
  if (lastSig === _VALUE_MEMBER) return true;            // so is a member expression
  if (lastSig === _STATEMENT_POSITION) return false;     // a statement may begin
  // A word: only the keywords that demand an expression leave one open. Read
  // with the same rule that CONSUMED it, so a non-ASCII identifier is a word
  // here too and divides like any other name.
  if (_isWordStart(lastSig.charAt(0))) return _REGEX_LEADING_KEYWORDS[lastSig] !== 1;
  // A number, a closing `)` `]` `}`, a string or template, or an increment —
  // `i++ / n` and `/a/ / n` both divide.
  //
  // `}` reaches here only when it closed an OBJECT. The brace that closes a
  // BLOCK reports a statement position instead, because a statement follows it
  // and a statement may begin with a pattern. Which one a brace is cannot be
  // read off the brace, so it is decided at the matching `{` — see
  // `_braceOpensObject`.
  return /^(?:[0-9]|[)\]}"'`]|\+\+|--)$/.test(lastSig);
}

// What counts as a WORD character is defined by what it is not, rather than by
// listing the characters that qualify. An identifier may be any Unicode
// letter — `var π = 4; π / 2` is ordinary source — and an ASCII-only
// list reads such a name as punctuation, which leaves the following division
// looking like a pattern and a real trailing comment surviving into what the
// presence gates read.
//
// So the punctuation the lexer knows how to handle is the list, and everything
// else outside a string, a template or a comment is part of a word. The two
// position markers begin with `@`, which is punctuation here and so can never
// be produced by this path.
var _NON_WORD = "{}()[];,.<>!=+-*/%&|^~?:\"'`\\@# \t\n\r";

function _isDigit(ch) {
  return ch >= "0" && ch <= "9";
}

// `-->` closes an HTML-like comment only where it OPENS a line; anywhere else
// it is a decrement against a greater-than, as in `while (i-->0)`.
function _atLineStart(emitted) {
  var nl = emitted.lastIndexOf("\n");
  var tail = nl === -1 ? emitted : emitted.slice(nl + 1);
  return tail.trim() === "";
}

// Character pairs that lex as ONE token when they meet. Two words always fuse;
// punctuation fuses only in these combinations, and the set is the language's
// multi-character punctuators, so unlike the lists this file has had to guess
// at, it is closed.
//
// `//` and `/*` are the ones that matter most: fusing a division against a
// following pattern would manufacture a comment out of two operators.
var _FUSABLE_PUNCTUATION = {
  "++": 1, "--": 1, "**": 1, "=>": 1, "==": 1, "!=": 1, "<=": 1, ">=": 1,
  "<<": 1, ">>": 1, "+=": 1, "-=": 1, "*=": 1, "/=": 1, "%=": 1, "&=": 1,
  "|=": 1, "^=": 1, "&&": 1, "||": 1, "??": 1, "?.": 1, "..": 1,
  "//": 1, "/*": 1, "*/": 1,
};

function _wouldFuse(prevCh, nextCh) {
  if (prevCh === "" || nextCh === "") return false;
  if (_isWordChar(prevCh) && _isWordChar(nextCh)) return true;
  return _FUSABLE_PUNCTUATION[prevCh + nextCh] === 1;
}

function _isWordChar(ch) {
  return ch !== "" && _NON_WORD.indexOf(ch) === -1;
}

function _isWordStart(ch) {
  return _isWordChar(ch) && !_isDigit(ch);
}

// Tokens that sit in what the slash rule calls an expression position but
// introduce a BODY rather than a value: `else`, `do`, and an arrow. Unlike the
// set of things a division may follow — which has been open-ended every time
// anyone has tried to write it down — this one is closed by the grammar.
//
// `try` and `finally` are here because they are ALWAYS followed by a body.
// They were added to the slash table above as statement-enders, which is true,
// and that alone made `try {` look like an object literal — so its closing
// brace became a value and a pattern statement after it was read as division.
// A keyword that ends a statement and a keyword that introduces a body are
// different questions, and both have to be answered for the same word.
var _BLOCK_INTRODUCERS = {
  "else": 1, "do": 1, "=>": 1, "try": 1, "finally": 1,
};

// Does this `{` open an object literal, or a block?
//
// An object opens where a VALUE is expected. A block opens where a STATEMENT
// is expected — the start of the file, after a `;`, inside another block,
// after a control-flow header, and after the three introducers above.
//
// Both readings of a brace are wrong for the other case, which is why the
// question is answered here and not at the `}`: treat every brace as a value
// and `if (ok) {} /[/*]/.test(x)` loses its source to a phantom comment; treat
// none as a value and the comment after `var q = {a: 1} / 2;` survives into
// what the presence gates read.
// A brace frame records two independent bits; an absent frame (unbalanced
// source) is treated as a block, which is the reading that cannot delete.
function _closesValue(frame) {
  return frame !== undefined && frame.closesValue === true;
}

// A pending `?` belongs to the brace nesting it was opened in, not to the file.
// Counted per FILE, the property colon in `cond ? {a: 1} : {}` closes the
// ternary early, and the real ternary colon is then read as a label — which
// makes the `{}` after it a block, its `}` a statement position, and the
// division after that a pattern that swallows the trailing comment.
function _ternaryScope(frame) {
  return frame.braces.length > 0 ? frame.braces[frame.braces.length - 1] : frame;
}

// `function` and `class` in an EXPRESSION position produce a value whose body
// is a block: `var q = function () {} / 2` divides, and `function f() {}
// /re/.test(x)` does not. The keyword is where the two are distinguishable —
// by the time the body brace arrives, both look identical.
var _EXPRESSION_BODY_KEYWORDS = { "function": 1, "class": 1 };

// Words that stand between a construct and the token that classifies it:
// `async function` and `for await (`. Looking only at the immediately
// preceding token reads the modifier instead of the position, which made an
// async function expression look like a declaration and a `for await` header
// look like a call.
var _TRANSPARENT_WORDS = { "async": 1, "await": 1 };

function _seeThrough(frame, lastSig) {
  if (_TRANSPARENT_WORDS[lastSig] !== 1) return lastSig;
  return frame.beforeWord[lastSig] === undefined ? "" : frame.beforeWord[lastSig];
}

// Where the template opening at `ts` ends, one past its closing backtick, or
// -1 when no closing backtick is reached.
function _templateEnd(source, ts) {
  var n = source.length;
  var i = ts + 1;
  while (i < n) {
    var c = source.charAt(i);
    if (c === "\\") { i += 2; continue; }
    if (c === "`") return i + 1;
    if (c === "$" && source.charAt(i + 1) === "{") {
      // Lexing answers this, and counting is the fallback for when it cannot.
      // The order was the other way round on the premise that counting either
      // gets it right or gives up, so the lexer was only needed where the count
      // returned nothing. That premise does not hold: counting skips strings
      // and nothing else, so a brace in a comment raises its depth and a later
      // one closes the substitution early. In `${1 /* { */}` the count walks
      // past the real end and accepts a `}` written in a line comment two lines
      // down, and everything between is swallowed as template text. Being
      // confidently wrong is worse than giving up, because the fallback never
      // runs. Measured on the six shapes that separate them, the lexed answer
      // is right in all six and the count is wrong in one and absent in two.
      var end = _lexedBraceEnd(source, i + 2);
      if (end === -1) end = _countingBraceEnd(source, i + 2);
      if (end === -1) return -1;
      i = end + 1;
      continue;
    }
    i += 1;
  }
  return -1;
}

// Where the substitution opening at `from` closes, decided by lexing its
// contents rather than counting characters. This is the answer taken first: it
// reads strings, comments, patterns and nested templates as the tokens they
// are, so a brace written inside any of them closes nothing.
function _lexedBraceEnd(source, from) {
  var toks;
  try { toks = tokenize(source.slice(from)); } catch (_e) { return -1; }
  var depth = 0;
  for (var i = 0; i < toks.length; i += 1) {
    if (toks[i].type !== TOK_PUNCT) continue;
    if (toks[i].value === "{") depth += 1;
    else if (toks[i].value === "}") {
      if (depth === 0) return from + toks[i].start;
      depth -= 1;
    }
  }
  return -1;
}

// Where a substitution ends, counted rather than lexed. It is the SECOND
// answer, reached only when the lexer above finds no closing brace at all,
// which is what a mis-read token there produces. A count that is wrong about a
// quoted brace still stops somewhere near, so it bounds that loss to the
// substitution rather than to everything after it. It skips strings and
// nothing else, so a brace in a comment, a pattern or a nested template is
// still counted as structural; that is why it no longer answers first.
function _countingBraceEnd(source, from) {
  var n = source.length;
  var d = 1;
  var k = from;
  while (k < n) {
    var c = source.charAt(k);
    // A brace written in a string is not structural. The places left where one
    // can be written and close nothing are a comment, a nested template and a
    // character class, and none of them can be found here.
    //
    // Skipping a `//`, a `/*` or a backtick reads each of them correctly and
    // reads `/[//]/`, `/[/*]/` and a backtick in a class incorrectly, because
    // whether the scan is INSIDE a pattern is the question it cannot answer.
    // Every such refinement is defeated by the same construct written inside a
    // pattern, so the count stays as narrow as it can be and the gaps are
    // listed rather than half-closed.
    //
    // A quote is not always opening a string: `/'/`, `[']` and `// it's` all
    // hold one that opens nothing, and skipping to the next quote from there
    // ran past the closing brace. What settles it without lexing is that a
    // string literal cannot hold a raw CR or LF, so a quote whose partner is
    // on another line, or absent, was not opening one. U+2028 and U+2029 are
    // NOT in that set: a string may hold either of them raw, so finding one
    // says nothing about whether a string is open.
    if (c === "'" || c === '"') {
      var j = k + 1;
      var closed = false;
      while (j < n) {
        var sc = source.charAt(j);
        if (sc === "\\") {
          // A line continuation, and `\` + CRLF is one of them rather than a
          // continuation followed by a bare LF that ends the string.
          j += (source.charCodeAt(j + 1) === 0x0D && source.charCodeAt(j + 2) === 0x0A)
            ? 3 : 2;
          continue;
        }
        if (sc === c) { closed = true; break; }
        var scc = source.charCodeAt(j);
        if (scc === 0x0A || scc === 0x0D) break;
        j += 1;
      }
      if (closed) { k = j + 1; continue; }
    }
    if (c === "{") d += 1;
    else if (c === "}") { d -= 1; if (d === 0) return k; }
    k += 1;
  }
  return -1;
}

// The `function` or `class` keyword whose body the brace about to be pushed
// opens, or null when the brace opens something else. Read by walking back
// from the brace over what may stand between it and that keyword: a balanced
// parameter list, the name, a generator star, and the `extends` clause of a
// class. Anything else means the brace is not a function or class body.
function _governingFunctionOrClass(tokens) {
  var i = tokens.length - 1;
  function skipTrivia() {
    while (i >= 0 && (tokens[i].type === TOK_WS || tokens[i].type === TOK_COMMENT)) i -= 1;
  }
  skipTrivia();
  // The parameter list, walked back to its opening paren.
  if (i >= 0 && tokens[i].type === TOK_PUNCT && tokens[i].value === ")") {
    var depth = 0;
    for (; i >= 0; i -= 1) {
      if (tokens[i].type !== TOK_PUNCT) continue;
      if (tokens[i].value === ")") depth += 1;
      else if (tokens[i].value === "(") {
        depth -= 1;
        if (depth === 0) { i -= 1; break; }
      }
    }
    if (depth !== 0) return null;
  }
  // The name, a generator star, and a class's extends clause. `extends` takes
  // an expression, so anything up to it is skipped the same way.
  var guard = 0;
  while (i >= 0 && guard < 64) {
    skipTrivia();
    if (i < 0) break;
    var t = tokens[i];
    if ((t.type === TOK_KEYWORD) && (t.value === "function" || t.value === "class")) return t;
    if (t.type === TOK_IDENT || (t.type === TOK_PUNCT && (t.value === "*" || t.value === "."))
        || (t.type === TOK_KEYWORD && (t.value === "extends" || t.value === "async"))) {
      i -= 1; guard += 1; continue;
    }
    return null;
  }
  return null;
}

function _braceOpensObject(lastSig) {
  if (lastSig === "") return false;                      // start of input
  if (lastSig === _STATEMENT_POSITION) return false;
  if (lastSig === ";" || lastSig === "{") return false;
  if (_BLOCK_INTRODUCERS[lastSig] === 1) return false;
  return !_slashDivides(lastSig);
}

function _regexCanStartHere(lastSig) {
  return !_slashDivides(lastSig);
}

// Reading back from `at` over the whitespace before it, was any of it a line
// terminator? Answers whether a semicolon was inserted between the previous
// word and this one.
function _lineBreakBackFrom(src, at) {
  for (var i = at - 1; i >= 0; i -= 1) {
    var cc = src.charCodeAt(i);
    if (LINE_TERMINATOR_CODES.indexOf(cc) !== -1) return true;
    if (cc !== 0x20 && cc !== 0x09 && cc !== 0x0B && cc !== 0x0C) return false;
  }
  return false;
}

// `onComment(start, end, kind)` is called for every comment the walk skips,
// with `end` exclusive and `kind` one of "line", "block", "html-open",
// "html-close". It exists so a caller that wants the RANGES rather than the
// stripped text asks this lexer instead of writing a second one: two answers to
// "where are the comments" drift, and the one that drifts is whichever is not
// the one the gates already trust.
//
// `onRegex(start, end, text)` is the same arrangement for pattern literals.
// This walk already has to know which slash opens one, since a `/*` inside a
// pattern opens no comment, and it carries the state that decides it: which
// brace closed a value, whether a colon ended a label, whether a keyword's
// line ended before the word after it. A caller that asks a second lexer the
// same question gets a second answer, and the one that drifts is the one the
// gates do not already trust.
function stripComments(src, onComment, onRegex) {
  // A mode STACK, not nested ad-hoc loops.
  //
  // Comment stripping is lexing, and the constructs nest: an interpolation
  // inside a template is CODE, that code may hold a string or another template,
  // and that template may interpolate again. Handling the template branch with
  // its own inner loop got this wrong twice running — first by treating a
  // template as one opaque string, so a comment inside `${...}` survived and a
  // gate could be silenced by it; then by counting braces without noticing that
  // a `}` inside a quoted string does not end the interpolation.
  //
  // As a stack both are the same rule and neither needs a special case: code
  // mode already knows how to skip a string, so an interpolation gets that for
  // free by BEING code.
  var out   = "";
  var i     = 0;
  var n     = src.length;
  // Each frame carries its own brace depth, because an interpolation ends at
  // the `}` that BALANCES its `${` — not at the first one. `${ {a:1}.a }` and
  // `${ JSON.stringify({a:{b:1}}) }` both close an inner object before the
  // interpolation ends, and a stack without depth handed the rest of the
  // expression back to template mode as literal text.
  //
  // The last significant character is per-FRAME for the same reason the depth
  // is. An interpolation begins a fresh expression, so `${/re/.test(x)}` opens
  // with a regex — but the character before it is the template's own backtick,
  // which is a value, and a single shared variable reads that as division and
  // leaves the regex unconsumed. The frame that ends restores the frame that
  // resumes.
  var stack = [{ mode: "code", depth: 0, lastSig: "", parens: [], braces: [], ternary: 0, fnExpr: [], beforeWord: {} }];

  while (i < n) {
    var top  = stack[stack.length - 1];
    var mode = top.mode;
    var lastSig = top.lastSig;
    var c = src.charAt(i);
    var d = src.charAt(i + 1);

    if (mode === "code") {
      if (c === "/" && d === "/") {
        var lineStart = i;
        while (i < n && src.charAt(i) !== "\n") i += 1;
        if (onComment) onComment(lineStart, i, "line");
        continue;
      }
      // The HTML-like comment forms. A script — which every file here is,
      // being CommonJS — treats `<!--` as a line comment and `-->` as one when
      // it opens a line, and Node parses them that way whether or not the file
      // is strict. Left standing they are code to this lexer and comment to the
      // runtime, which is the direction that hides things: a token inside one
      // would read as live and exempt the file.
      if (c === "<" && src.substr(i, 4) === "<!--") {
        var htmlOpenStart = i;
        while (i < n && src.charAt(i) !== "\n") i += 1;
        if (onComment) onComment(htmlOpenStart, i, "html-open");
        continue;
      }
      if (c === "-" && src.substr(i, 3) === "-->" && _atLineStart(out)) {
        var htmlCloseStart = i;
        while (i < n && src.charAt(i) !== "\n") i += 1;
        if (onComment) onComment(htmlCloseStart, i, "html-close");
        continue;
      }
      if (c === "/" && d === "*") {
        var blockStart = i;
        i += 2;
        var spannedLines = false;
        while (i < n && !(src.charAt(i) === "*" && src.charAt(i + 1) === "/")) {
          if (src.charAt(i) === "\n") {              // keep line numbers honest
            out += "\n";
            spannedLines = true;
          }
          i += 1;
        }
        i += 2;
        if (onComment) onComment(blockStart, i, "block");
        // A block comment can SEPARATE two tokens — `foo/* note */in obj`, or
        // `a +/* note */+b` — and deleting it outright fuses them into `fooin`
        // and `a ++b`, which are different programs. One space restores the
        // boundary.
        //
        // Only where they would actually fuse, though: `f(/* x */a)` must stay
        // `f(a)`, because the detectors match source shapes and an inserted
        // space would make an adjacency pattern stop matching — a miss, and so
        // silent. A comment that spanned lines already emitted a newline, which
        // separates them.
        if (!spannedLines &&
            _wouldFuse(out.charAt(out.length - 1), src.charAt(i))) {
          out += " ";
        }
        continue;
      }
      if (c === "\"" || c === "'") {
        out += c;
        i   += 1;
        while (i < n) {
          if (src.charAt(i) === "\\") { out += src.substr(i, 2); i += 2; continue; }
          out += src.charAt(i);
          if (src.charAt(i) === c) { i += 1; break; }
          i += 1;
        }
        top.lastSig = c;                          // a string is a value
        continue;
      }
      // A REGEX LITERAL is a lexical unit: `/` and `}` and quote characters
      // inside it are literal text. Skipping that deleted code: the untracked
      // version ate everything after `/^curl\//i` in the bot-guard agent list,
      // and inside an interpolation a `}` in a regex ended the `${` early and
      // left the following comment as template text.
      if (c === "/" && _regexCanStartHere(lastSig)) {
        var rxStart = i;
        i += 1;
        var inClass = false;
        while (i < n) {
          var r = src.charAt(i);
          if (r === "\\") { i += 2; continue; }
          if (r === "\n") break;                  // unterminated: not a regex
          if (inClass) { if (r === "]") inClass = false; }
          else if (r === "[") inClass = true;
          else if (r === "/") { i += 1; break; }
          i += 1;
        }
        while (i < n && /[a-z]/.test(src.charAt(i))) i += 1;   // flags
        out += src.slice(rxStart, i);
        if (typeof onRegex === "function") onRegex(rxStart, i, src.slice(rxStart, i));
        top.lastSig = _VALUE_REGEX;               // a pattern is a value
        continue;
      }
      if (c === "`") {
        out += c;
        i   += 1;
        // Recorded on the frame that RESUMES when the template closes, so the
        // `/` in `` `x`/2 `` divides.
        top.lastSig = "`";
        stack.push({ mode: "template", depth: 0, lastSig: "", parens: [], braces: [], ternary: 0, fnExpr: [], beforeWord: {} });
        continue;
      }
      if (c === "{") {
        top.depth += 1;
        // Two bits, because they are not the same question. Whether the braces
        // hold an OBJECT decides what a colon inside them means. Whether the
        // closing brace is a VALUE decides how a slash after it reads — and a
        // function or class EXPRESSION has a block for a body and is still a
        // value, so `var q = function () {} / 2` divides.
        var opensObject = _braceOpensObject(lastSig);
        var pending     = top.fnExpr[top.fnExpr.length - 1];
        var isFnBody    = pending !== undefined && pending.depth === top.parens.length;
        if (isFnBody) top.fnExpr.pop();
        // An arrow's body is the token immediately after the `=>`, and an
        // arrow function is always a value: `var f = () => {} / 2` divides.
        // The body is a block all the same, so only the closing bit changes.
        var isArrowBody = lastSig === "=>";
        top.braces.push({
          isObject:    opensObject,
          closesValue: opensObject || isArrowBody ||
                       (isFnBody && pending.isExpr === true),
          ternary:     0,
        });
        out += c;
        i   += 1;
        top.lastSig = c;
        continue;
      }
      if (c === "}") {
        // Balances an inner block or object: still inside the interpolation.
        if (top.depth > 0) {
          top.depth -= 1;
          out += c;
          i   += 1;
          // An object, or the body of a function or class EXPRESSION, is a
          // value, so a slash after it divides. A plain block is not: the
          // statement that follows may begin with a pattern, which is the same
          // open position as the start of input.
          top.lastSig = _closesValue(top.braces.pop()) ? c : _STATEMENT_POSITION;
          continue;
        }
        // Balances the `${` itself, and only when a template opened this frame.
        if (stack.length > 1 && stack[stack.length - 2].mode === "template") {
          out += c;
          i   += 1;
          stack.pop();
          continue;
        }
        out += c;
        i   += 1;
        top.lastSig = _closesValue(top.braces.pop()) ? c : _STATEMENT_POSITION;
        continue;
      }
      // A `?` that opens a conditional, told apart from `??` and `?.` — both of
      // which are operators, not the start of a ternary whose `:` is coming.
      if (c === "?") {
        if (d === "?" || d === ".") {
          out += c + d;
          i   += 2;
          top.lastSig = c + d;
          continue;
        }
        _ternaryScope(top).ternary += 1;
        out += c;
        i   += 1;
        top.lastSig = c;
        continue;
      }
      // A colon means three different things, and only one of them is followed
      // by a value:
      //
      //   - closing a ternary — `c ? 1 : {a: 1}` — a value follows;
      //   - separating a property from its value inside an object — likewise;
      //   - ending a label or a `case`, where a STATEMENT follows, and that
      //     statement may be a block or begin with a pattern.
      //
      // Read as a value in the third case, `label: {}` becomes an object whose
      // closing brace is a value, and the pattern statement after it is deleted.
      if (c === ":") {
        out += c;
        i   += 1;
        var scope = _ternaryScope(top);
        if (scope.ternary > 0) {
          scope.ternary -= 1;
          top.lastSig = c;
          continue;
        }
        var innermost = top.braces[top.braces.length - 1];
        var insideObject = innermost !== undefined && innermost.isObject === true;
        top.lastSig = insideObject ? c : _STATEMENT_POSITION;
        continue;
      }
      if (c === "(") {
        top.parens.push(_CONTROL_HEADER_KEYWORDS[_seeThrough(top, lastSig)] === 1);
        out += c;
        i   += 1;
        top.lastSig = c;
        continue;
      }
      if (c === ")") {
        var wasControlHeader = top.parens.pop() === true;
        out += c;
        i   += 1;
        // A control-flow header is followed by the statement it governs, which
        // may begin with a pattern or with a block.
        top.lastSig = wasControlHeader ? _STATEMENT_POSITION : c;
        continue;
      }
      // An arrow is one token: the `>` alone reads as an operator, which would
      // make the body brace that follows look like an object literal.
      if (c === "=" && d === ">") {
        out += "=>";
        i   += 2;
        top.lastSig = "=>";
        continue;
      }
      // `++` and `--` are consumed as one token for the same reason: the
      // second character alone reads as an operator, which would leave an
      // expression position open, and `i++ / count` is a division.
      if ((c === "+" || c === "-") && d === c) {
        out += c + d;
        i   += 2;
        top.lastSig = c + d;
        continue;
      }
      // An IDENTIFIER is consumed whole, because the regex-or-division rule
      // asks which word preceded the slash and a single trailing character
      // cannot answer that: `return` and `counter` both end in a letter.
      // A NUMERIC LITERAL is consumed whole, before words, because its
      // spellings end in different kinds of character: `1.` in a dot, `0x1F`
      // in a letter, `1_000n` in an `n`. Any of those left as the last thing
      // seen makes the division after it look like a pattern.
      if (_isDigit(c) || (c === "." && _isDigit(d))) {
        var numStart = i;
        i += 1;
        while (i < n) {
          var nc = src.charAt(i);
          // An exponent sign belongs to the number; a `+` or `-` anywhere else
          // is an operator and ends it.
          if ((nc === "+" || nc === "-") &&
              (src.charAt(i - 1) === "e" || src.charAt(i - 1) === "E")) {
            i += 1;
            continue;
          }
          if (_isDigit(nc) || nc === "." || nc === "_" ||
              "abcdefABCDEFxXoObBnN".indexOf(nc) !== -1) {
            i += 1;
            continue;
          }
          break;
        }
        out += src.slice(numStart, i);
        top.lastSig = _VALUE_NUMBER;
        continue;
      }
      if (_isWordStart(c)) {
        var wStart = i;
        while (i < n && _isWordChar(src.charAt(i))) i += 1;
        var word = src.slice(wStart, i);
        out += word;
        // Recorded here and read at the body brace, because the name and the
        // parameter list sit between them and neither says which this was.
        //
        // The question is the same one a brace asks: `function` is an
        // expression exactly where a `{` would be an object literal, and a
        // declaration exactly where a `{` would be a block. Asking whether a
        // SLASH could start a pattern there is a different question with a
        // different answer — a statement position allows a pattern and holds a
        // declaration — and using it read every declaration as an expression.
        //
        // Recorded WITH the paren depth it was seen at, because the body brace
        // is not the next brace: `function (a = {}) {}` has a parameter default
        // in between, and a single pending flag was spent on it, leaving the
        // real body classified as a plain block. The body is the brace that
        // arrives back at the depth where the keyword was read.
        //
        // `async` and `await` are TRANSPARENT for the questions asked further
        // on. In `var q = async function () {}` the token before `function` is
        // `async`, which reads as an ordinary name and so as a declaration; in
        // `for await (...)` the token before the paren is `await`, so the paren
        // is not recognised as a loop header. Both are answered by the position
        // the transparent word ITSELF was in, so that is what gets kept.
        //
        // None of that applies to a word that is not the keyword it spells, and
        // two positions decide that for it rather than the word deciding for
        // itself.
        //
        // After a dot it is a PROPERTY NAME. `o.function` must not open a
        // pending function-body record for a brace further on to spend, and
        // `o.default / 2` must divide.
        //
        // After `break` or `continue` it is a LABEL, and the jump statement ends
        // with it. `break outer / x` is not a continuation, so a newline inserts
        // the semicolon — which puts a slash on the next line at the start of a
        // statement, where it opens a pattern. Read as an ordinary name it
        // divided instead, and the `/*` inside that pattern opened a phantom
        // comment that ran to the end of the file.
        if (lastSig === ".") {
          top.lastSig = _VALUE_MEMBER;
          continue;
        }
        // A word after `break` or `continue` is the LABEL they take, but only
        // on the same line: both forbid a line terminator before the label, so
        // one there ends the statement and this word begins the next.
        if (lastSig === "break" || lastSig === "continue") {
          if (!_lineBreakBackFrom(src, wStart)) {
            top.lastSig = _STATEMENT_POSITION;      // the word is the label
            continue;
          }
          // The line terminator ended the jump statement, so this word begins
          // a new one and is read from statement position. Leaving the jump
          // keyword in place made `break` + newline + `function f() {}` an
          // expression, and the pattern after its brace read as division.
          lastSig = _STATEMENT_POSITION;
        }
        if (_TRANSPARENT_WORDS[word] === 1) top.beforeWord[word] = lastSig;
        if (_EXPRESSION_BODY_KEYWORDS[word] === 1) {
          top.fnExpr.push({
            depth:  top.parens.length,
            isExpr: _braceOpensObject(_seeThrough(top, lastSig)),
          });
        }
        top.lastSig = word;
        continue;
      }
      out += c;
      i   += 1;
      if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") top.lastSig = c;
      continue;
    }

    // mode === "template": literal TEXT, to the closing backtick or a `${`.
    if (c === "\\") { out += src.substr(i, 2); i += 2; continue; }
    if (c === "$" && d === "{") {
      out += "${";
      i   += 2;
      // An interpolation opens a fresh expression: a `/` here is a regex.
      stack.push({ mode: "code", depth: 0, lastSig: "", parens: [], braces: [], ternary: 0, fnExpr: [], beforeWord: {} });
      continue;
    }
    if (c === "`") { out += c; i += 1; stack.pop(); continue; }
    out += c;
    i   += 1;
  }
  return out;
}

// Every comment in `src`, as `{ start, end, kind }` with `end` exclusive, in
// source order. The same walk `stripComments` performs, reporting the ranges
// instead of the text between them -- so a caller that EXCISES comments and a
// gate that FINDS them cannot disagree about what a comment is. `//` appears
// inside strings, regex literals and template interpolations throughout this
// tree, which is why neither can be a regex.
function commentRanges(src) {
  var ranges = [];
  stripComments(src, function (start, end, kind) {
    ranges.push({ start: start, end: end, kind: kind });
  });
  return ranges;
}

module.exports = {
  tokenize:           tokenize,
  stripComments:      stripComments,
  commentRanges:      commentRanges,
  // Exported for the same reason `commentRanges` is: a caller that EXCISES a
  // comment has to answer "would these two characters have fused" the way the
  // stripper does. `foo/* note */bar` becomes `foobar` without it, and
  // `f(/* x */a)` gains a space it should not have with a coarser rule.
  wouldFuse:          _wouldFuse,
  significantTokens:  significantTokens,
  findCalls:          findCalls,
  findEnclosingTry:   findEnclosingTry,
  findEnclosingFn:    findEnclosingFn,
  aliasesOf:          aliasesOf,
  positionToLineCol:  positionToLineCol,
  TOK_IDENT:          TOK_IDENT,
  TOK_PUNCT:          TOK_PUNCT,
  TOK_STRING:         TOK_STRING,
  TOK_KEYWORD:        TOK_KEYWORD,
  TOK_NUMBER:         TOK_NUMBER,
  TOK_REGEX:          TOK_REGEX,
  TOK_TEMPLATE:       TOK_TEMPLATE,
};
