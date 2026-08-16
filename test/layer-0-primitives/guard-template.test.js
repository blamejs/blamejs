// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-template — SSTI content-safety primitive (b.guardTemplate).
 *
 * Covers the pass-through-or-throw sanitize contract: benign text returns
 * unchanged, while a string carrying template-engine syntax throws
 * GuardTemplateError with the offending rule id. Jinja `{{...}}` / ERB
 * `<%...%>` / Pug interpolation shapes are refused at EVERY profile —
 * the SSTI class is never an operator opt-in.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

function testGuardTemplateSurface() {
  check("guardTemplate is an object",           typeof b.guardTemplate === "object");
  check("guardTemplate.NAME === 'template'",    b.guardTemplate.NAME === "template");
  check("guardTemplate.sanitize is a function", typeof b.guardTemplate.sanitize === "function");
  check("guardTemplate registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "template"; }));
  check("frameworkError.GuardTemplateError exposed",
    typeof b.frameworkError.GuardTemplateError === "function");
}

function testSanitizeCleanPassthrough() {
  // Plain prose with no engine syntax survives sanitize verbatim.
  var out = b.guardTemplate.sanitize("Hello world", { profile: "strict" });
  check("benign text passes through unchanged", out === "Hello world");
}

function testSanitizeRefusesJinjaExpression() {
  // `{{7*7}}` is the canonical SSTI probe (Jinja / Twig / Handlebars).
  check("jinja expression refused under strict",
    _code(function () { b.guardTemplate.sanitize("Hello {{7*7}}", { profile: "strict" }); })
      === "template.jinja-expression");
}

function testSanitizeRefusesErbEveryProfile() {
  // ERB `<%= ... %>` interpolation is refused even at permissive.
  check("ERB expression refused at permissive",
    _code(function () { b.guardTemplate.sanitize("x <%= 7 %>", { profile: "permissive" }); })
      === "template.erb-expression");
}

function testSanitizeThrowsGuardTemplateError() {
  var caught = null;
  try { b.guardTemplate.sanitize("#{name}", { profile: "strict" }); }
  catch (e) { caught = e; }
  check("sanitize throws a GuardTemplateError instance",
    caught instanceof b.frameworkError.GuardTemplateError);
}

// The template-engine screens are character walks. Each is compared against
// the pattern it replaced, over the delimiter shapes — complete, unbalanced,
// and split across lines — an SSTI payload is written in.
function testTemplateScreensAgreeWithThePatternsTheyReplaced() {
  var JINJA_EXPR_RE   = /\{\{[\s\S]*?\}\}/;
  var JINJA_STMT_RE   = /\{%[\s\S]*?%\}/;
  var ERB_EXPR_RE     = /<%[\s\S]*?%>/;
  var PUG_INTERP_RE   = /[#!]\{[\s\S]*?\}/;
  var DOLLAR_BRACE_RE = /\$\{[\s\S]*?\}/;
  var VELOCITY_DIR_RE = /#(?:set|if|else|elseif|end|foreach|parse|include|stop)\b/i;

  var INPUTS = ["", "plain text", "{{ x }}", "{{x}}", "{{", "}}", "{{ }}",
    "{{\nmulti\n}}", "a {{ b }} c", "{%if x%}", "{%", "%}", "{% %}",
    "<% code %>", "<%", "%>", "<%= x %>", "#{x}", "!{x}", "#{", "!{",
    "#{ }", "${x}", "${", "}", "${ }", "${a{b}", "#set($x=1)", "#SET(1)",
    "#if(true)", "#ends", "#end", "#endfor", "#foreach($a in $b)", "#stopping",
    "#stop", "#parse('x')", "# set", "no directives", "css #id { color: red }",
    "{{a}}{{b}}", "text with } brace", "text with { brace"];

  var diffs = [];
  INPUTS.forEach(function (s) {
    var kinds = b.guardTemplate.validate(s, { profile: "strict" }).issues
      .map(function (i) { return i.kind; });
    function has(k) { return kinds.indexOf(k) !== -1; }
    function compare(label, expected, actual) {
      if (expected !== actual) diffs.push(label + " " + JSON.stringify(s));
    }
    compare("jinja-expression", JINJA_EXPR_RE.test(s), has("jinja-expression"));
    compare("jinja-statement", JINJA_STMT_RE.test(s), has("jinja-statement"));
    compare("erb-expression", ERB_EXPR_RE.test(s), has("erb-expression"));
    compare("pug-interpolation", PUG_INTERP_RE.test(s), has("pug-interpolation"));
    compare("dollar-brace", DOLLAR_BRACE_RE.test(s), has("dollar-brace"));
    compare("velocity-directive", VELOCITY_DIR_RE.test(s), has("velocity-directive"));
  });
  check("every template screen agrees with the pattern it replaced (" +
        INPUTS.length + " inputs)", diffs.length === 0,
        diffs.slice(0, 5).join(" | "));
}

function run() {
  testTemplateScreensAgreeWithThePatternsTheyReplaced();
  testGuardTemplateSurface();
  testSanitizeCleanPassthrough();
  testSanitizeRefusesJinjaExpression();
  testSanitizeRefusesErbEveryProfile();
  testSanitizeThrowsGuardTemplateError();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-template] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
