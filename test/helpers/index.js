// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/helpers — shared infrastructure for the per-file test layout.
 *
 * Each test file imports the named helpers it needs:
 *
 *   var { check, b }              = require("../helpers");
 *   var { setupTestDb }           = require("../helpers/db");
 *   var { _bodyReq, _bodyRes }    = require("../helpers/mocks");
 *
 * This index re-exports every named helper so the most common case
 * (a single require) covers most files. Files needing specific
 * helpers can import per-module to make their dependencies obvious.
 *
 * Legacy `require("../_helpers")` continues to work — _helpers.js is
 * a thin re-export shim for the migration window.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../../index.js");

var _check    = require("./check");
var _db       = require("./db");
var _drivers  = require("./drivers");
var _mocks    = require("./mocks");
var _cluster  = require("./cluster");
var _http     = require("./http");
var _otel     = require("./otel");
var _wait     = require("./wait");
var _fsWatch  = require("./fs-watch");
var _tls      = require("./tls");
var _ocsp     = require("./ocsp");
var _merkle   = require("./merkle");
var _webauthn = require("./webauthn");
var _policyVocab = require("./policy-vocabulary");

module.exports = {
  // Framework binding + Node stdlib re-exports for ergonomics.
  b:    b,
  fs:   fs,
  os:   os,
  path: path,

  // Assertion + counter
  check:              _check.check,
  getChecks:          _check.getChecks,
  resetChecksForTest: _check.resetChecksForTest,
  addExternalChecks:  _check.addExternalChecks,
  formatErr:          _check.formatErr,

  // DB fixtures
  setupTestDb:           _db.setupTestDb,
  teardownTestDb:        _db.teardownTestDb,
  setupTestDbForMW:      _db.setupTestDbForMW,
  teardownMW:            _db.teardownMW,
  setupVaultOnly:        _db.setupVaultOnly,
  teardownVaultOnly:     _db.teardownVaultOnly,
  setTestPassphraseEnv:  _db.setTestPassphraseEnv,
  TEST_PASSPHRASE:       _db.TEST_PASSPHRASE,

  // Driver fakes
  _makeFakeDriver:         _drivers._makeFakeDriver,
  _makeSqliteDriver:       _drivers._makeSqliteDriver,
  _makeFakeMysqlDriver:    _drivers._makeFakeMysqlDriver,
  _makeFakeServiceAccount: _drivers._makeFakeServiceAccount,

  // HTTP mocks
  _mockReq:      _mocks._mockReq,
  _mockRes:      _mocks._mockRes,
  _bodyReq:      _mocks._bodyReq,
  _bodyRes:      _mocks._bodyRes,
  _streamingRes: _mocks._streamingRes,

  // Cluster fixture
  _setupClusterGateFixture: _cluster._setupClusterGateFixture,
  _expectNotLeaderError:    _cluster._expectNotLeaderError,

  // HTTP helpers
  listenOnRandomPort: _http.listenOnRandomPort,

  // End-of-file teardown: retire the httpClient pool and wait for every
  // socket and pending file operation to finish, so a leak fails in the file
  // that caused it rather than as a watchdog kill nobody can attribute.
  drainOpenHandles:   _http.drainOpenHandles,

  // The same drain, run so it cannot swallow the failure that preceded it.
  // Prefer this over `try { ... } finally { await drainOpenHandles(...) }`:
  // a throw from a `finally` replaces the body's error, so the check that
  // actually failed is lost and the leak its skipped teardown caused is all
  // that gets reported.
  withDrain:          _http.withDrain,

  // Loopback TLS server certificate (verify with `ca: [pair.cert]`)
  selfSignedPair:     _tls.selfSignedPair,
  registerCredential: _webauthn.registerCredential,
  assertCredential:   _webauthn.assertCredential,

  // RFC 6960 OCSP responder — one parameterized builder for the accept path
  // and every refusal shape (status, certStatus, nonce, CertID, signature).
  buildOcspResponse:  _ocsp.buildOcspResponse,

  // RFC 9162 Merkle tree — the recursive definitions, for checking the
  // framework's iterative proof walk against real trees and real proofs.
  merkle:             _merkle,
  synthCertForOcsp:   _ocsp.synthCert,

  // OTel fake (for tracing + observability tests)
  makeFakeOtelApi:    _otel.makeFakeOtelApi,

  // Poll-until-condition — replaces fixed-budget setTimeout(r, N)
  // sleeps that flake under SMOKE_PARALLEL=64 + macOS contention.
  waitUntil:          _wait.waitUntil,
  waitUntilEqual:     _wait.waitUntilEqual,

  // Real-time passive observation budget — for verifying ABSENCE of
  // an event over a window. Distinct from waitUntil's poll-until-true.
  passiveObserve:     _wait.passiveObserve,

  // fs.watch / fs.watchFile test primitives
  backdateFile:       _fsWatch.backdateFile,
  waitForWatcher:     _fsWatch.waitForWatcher,
  withTestTimeout:    _wait.withTestTimeout,

  // Guard policy-vocabulary assertion (see helpers/policy-vocabulary.js).
  assertPolicyVocabulary: _policyVocab.assertPolicyVocabulary,
};
