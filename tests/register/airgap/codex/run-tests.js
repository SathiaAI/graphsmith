"use strict";

const crypto = require("crypto");
const http = require("http");
const https = require("https");
const net = require("net");
const airgap = require("../../../../checks/register-airgap.js");

const tests = [];
const add = (name, fn) => tests.push({ name, fn });
const inspect = (v) => {
  try { return JSON.stringify(v); } catch (e) { return String(v); }
};
const expectStatus = (actual, expected) => {
  if (!actual || actual.status !== expected) {
    throw new Error("expected status " + expected + ", got " + inspect(actual));
  }
};
const expectNoThrowStatus = (fn, allowed) => {
  let result;
  try { result = fn(); } catch (e) {
    throw new Error("CRASH " + e.name + ": " + e.message);
  }
  if (!result || !allowed.includes(result.status)) {
    throw new Error("expected status in " + allowed.join("|") + ", got " + inspect(result));
  }
  return result;
};

const ed = crypto.generateKeyPairSync("ed25519");
const ed2 = crypto.generateKeyPairSync("ed25519");
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = (key) => key.export({ type: "spki", format: "pem" }).toString();
const baseManifest = () => ({
  schema_version: "1.0",
  kind: "release",
  release: "v0.3.0",
  files: [{ path: "a.js", sha256: "a".repeat(64) }],
});
const hashManifest = (manifest) =>
  airgap.sha256Hex(Buffer.from(airgap.canonicalize(manifest), "utf8"));
const signHash = (hash, privateKey, algorithm, options) =>
  crypto.sign(algorithm, Buffer.from(hash, "utf8"),
    options ? { key: privateKey, ...options } : privateKey).toString("base64");
const fixture = (overrides = {}) => {
  const manifest = overrides.manifest || baseManifest();
  const hash = hashManifest(manifest);
  const signature = {
    schema_version: "1.0",
    algo: "ed25519",
    signer: "maintainer-1",
    manifest_sha256: hash,
    value: signHash(hash, ed.privateKey, null),
    delivery: "out-of-band",
    ...(overrides.signature || {}),
  };
  return {
    manifest,
    signature,
    trustedKeys: overrides.trustedKeys || { "maintainer-1": pem(ed.publicKey) },
    ...(Object.prototype.hasOwnProperty.call(overrides, "files") ? { files: overrides.files } : {}),
  };
};

add("baseline genuine trusted Ed25519 signature verifies", () =>
  expectStatus(airgap.run(fixture()), "verified"));

add("missing signature is never verified", () =>
  expectStatus(airgap.run({ manifest: baseManifest(), trustedKeys: {} }), "not-applicable"));

add("manifest hash mismatch fails", () => {
  const f = fixture();
  f.manifest.release = "v9.9.9";
  expectStatus(airgap.run(f), "failed");
});

add("forged signature fails", () => {
  const f = fixture();
  f.signature.value = signHash(f.signature.manifest_sha256, ed2.privateKey, null);
  expectStatus(airgap.run(f), "failed");
});

add("replayed signature from another manifest fails", () => {
  const signed = fixture();
  signed.manifest = { ...signed.manifest, release: "different" };
  expectStatus(airgap.run(signed), "failed");
});

add("unknown signer is unavailable", () => {
  const f = fixture({ trustedKeys: {} });
  expectStatus(airgap.run(f), "unavailable");
});

add("delivery other than out-of-band fails", () => {
  const f = fixture({ signature: { delivery: "registry" } });
  expectStatus(airgap.run(f), "failed");
});

add("missing required signature field fails", () => {
  const f = fixture();
  delete f.signature.delivery;
  expectStatus(airgap.run(f), "failed");
});

add("extra signature field fails per additionalProperties false", () => {
  const f = fixture({ signature: { attacker_controlled: true } });
  expectStatus(airgap.run(f), "failed");
});

add("inherited signature fields fail schema shape", () => {
  const f = fixture();
  f.signature = Object.create(f.signature);
  expectStatus(airgap.run(f), "failed");
});

add("invalid base64 signature fails", () => {
  const f = fixture({ signature: { value: "!!!!not-base64!!!!" } });
  expectStatus(airgap.run(f), "failed");
});

add("wrong trusted Ed25519 key fails", () => {
  const f = fixture({ trustedKeys: { "maintainer-1": pem(ed2.publicKey) } });
  expectStatus(airgap.run(f), "failed");
});

add("ECDSA declaration rejects RSA PKCS1v1.5 key/signature", () => {
  const manifest = baseManifest();
  const hash = hashManifest(manifest);
  const f = fixture({
    manifest,
    signature: {
      algo: "ecdsa-p256-sha256",
      value: signHash(hash, rsa.privateKey, "sha256"),
    },
    trustedKeys: { "maintainer-1": pem(rsa.publicKey) },
  });
  expectStatus(airgap.run(f), "failed");
});

add("RSA-PSS declaration rejects EC key/signature", () => {
  const manifest = baseManifest();
  const hash = hashManifest(manifest);
  const f = fixture({
    manifest,
    signature: {
      algo: "rsa-pss-sha256",
      value: signHash(hash, ec.privateKey, "sha256"),
    },
    trustedKeys: { "maintainer-1": pem(ec.publicKey) },
  });
  expectStatus(airgap.run(f), "failed");
});

add("valid ECDSA P-256 signature verifies", () => {
  const manifest = baseManifest();
  const hash = hashManifest(manifest);
  const f = fixture({
    manifest,
    signature: {
      algo: "ecdsa-p256-sha256",
      value: signHash(hash, ec.privateKey, "sha256"),
    },
    trustedKeys: { "maintainer-1": pem(ec.publicKey) },
  });
  expectStatus(airgap.run(f), "verified");
});

add("valid RSA-PSS signature verifies", () => {
  const manifest = baseManifest();
  const hash = hashManifest(manifest);
  const f = fixture({
    manifest,
    signature: {
      algo: "rsa-pss-sha256",
      value: signHash(hash, rsa.privateKey, "sha256",
        { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }),
    },
    trustedKeys: { "maintainer-1": pem(rsa.publicKey) },
  });
  expectStatus(airgap.run(f), "verified");
});

add("non-canonical JSON serialization hash fails", () => {
  const manifest = { z: 1, a: 2 };
  const wrongHash = airgap.sha256Hex(Buffer.from(JSON.stringify(manifest), "utf8"));
  const f = fixture({
    manifest,
    signature: {
      manifest_sha256: wrongHash,
      value: signHash(wrongHash, ed.privateKey, null),
    },
  });
  expectStatus(airgap.run(f), "failed");
});

add("unicode manifest requires and accepts genuine signature", () => {
  const manifest = { release: "雪\u2028😀e\u0301", files: [] };
  expectStatus(airgap.run(fixture({ manifest })), "verified");
});

add("huge forged value does not verify", () => {
  const f = fixture({ signature: { value: "A".repeat(1024 * 1024) } });
  expectStatus(airgap.run(f), "failed");
});

add("binary manifest with forged signature does not verify", () => {
  const manifest = { payload: Buffer.from([0, 255, 1]), files: [] };
  const f = fixture({ manifest });
  f.signature.value = signHash(f.signature.manifest_sha256, ed2.privateKey, null);
  expectStatus(airgap.run(f), "failed");
});

add("prototype-polluted files map cannot fake matches-disk", () => {
  const path = "__codex_airgap_absent_file__";
  const manifest = { release: "v0.3.0", files: [{ path, sha256: "b".repeat(64) }] };
  const f = fixture({ manifest, files: {} });
  Object.prototype[path] = "b".repeat(64);
  try {
    expectStatus(airgap.run(f), "failed");
  } finally {
    delete Object.prototype[path];
  }
});

add("clock and randomness are not decision inputs", () => {
  const oldNow = Date.now;
  const oldRandom = Math.random;
  Date.now = () => { throw new Error("Date.now accessed"); };
  Math.random = () => { throw new Error("Math.random accessed"); };
  try { expectStatus(airgap.run(fixture()), "verified"); }
  finally { Date.now = oldNow; Math.random = oldRandom; }
});

add("signer identity does not override invalid cryptography", () => {
  const f = fixture();
  f.signature.value = signHash(f.signature.manifest_sha256, ed2.privateKey, null);
  expectStatus(airgap.run(f), "failed");
});

add("decision path performs no network calls", () => {
  let calls = 0;
  const originals = {
    request: http.request, get: http.get, srequest: https.request, sget: https.get,
    connect: net.connect, createConnection: net.createConnection,
  };
  const hit = () => { calls++; throw new Error("network accessed"); };
  http.request = hit; http.get = hit; https.request = hit; https.get = hit;
  net.connect = hit; net.createConnection = hit;
  try { expectStatus(airgap.run(fixture()), "verified"); }
  finally {
    http.request = originals.request; http.get = originals.get;
    https.request = originals.srequest; https.get = originals.sget;
    net.connect = originals.connect; net.createConnection = originals.createConnection;
  }
  if (calls !== 0) throw new Error("observed " + calls + " network call(s)");
});

add("BigInt manifest never crashes", () => {
  const f = fixture();
  f.manifest = { release: 1n };
  expectNoThrowStatus(() => airgap.run(f), ["failed"]);
});

add("circular manifest never crashes", () => {
  const f = fixture();
  const manifest = { release: "cycle" };
  manifest.self = manifest;
  f.manifest = manifest;
  expectNoThrowStatus(() => airgap.run(f), ["failed"]);
});

add("throwing context getter never crashes", () => {
  const ctx = {};
  Object.defineProperty(ctx, "manifest", {
    enumerable: true,
    get() { throw new Error("hostile getter"); },
  });
  expectNoThrowStatus(() => airgap.run(ctx), ["failed"]);
});

add("proxy manifest ownKeys trap never crashes", () => {
  const f = fixture();
  f.manifest = new Proxy({}, {
    ownKeys() { throw new Error("hostile ownKeys"); },
  });
  expectNoThrowStatus(() => airgap.run(f), ["failed"]);
});

let pass = 0;
let fail = 0;
for (const test of tests) {
  try {
    test.fn();
    pass++;
    console.log("PASS " + test.name);
  } catch (e) {
    fail++;
    console.log("FAIL " + test.name + " " + e.message);
  }
}
console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
process.exitCode = fail === 0 ? 0 : 1;
