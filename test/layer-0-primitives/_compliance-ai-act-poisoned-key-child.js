// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// b.pick.registerPoisonedKeys only ever grows its set, and nothing removes a
// name from it, so registering one inside the test file would poison that name
// for every later assertion in the same process. This runs as its own process
// and reports what the signed adherence document ended up carrying.
//
// argv[2] is the package root, resolved by the caller.

var b = require(process.argv[2]);

// A name the adherence form reads, registered as unsafe by an application's
// object layer. declareAdherence validates it, then forwards it to the form.
b.pick.registerPoisonedKeys(["provider"]);

var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
var hash = b.crypto.sha3Hash("annex-xi-technical-documentation-v1");
var commitments = ["Art. 53(1)(a)", "Art. 53(1)(b)", "Art. 53(1)(c)", "Art. 53(1)(d)"]
  .map(function (article) {
    return { article: article, statement: "covered", evidenceHash: hash };
  });

var out = { provider: null, error: null };
try {
  var env = b.compliance.aiAct.gpai.declareAdherence({
    modelId:       "acme-llm-7b",
    modelVersion:  "1.0",
    provider:      { name: "Acme" },
    commitments:   commitments,
    privateKeyPem: pair.privateKey,
  });
  out.provider = env.adherence.provider;
} catch (e) {
  out.error = (e && e.code) || (e && e.message) || String(e);
}
process.stdout.write(JSON.stringify(out));
