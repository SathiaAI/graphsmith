const crypto = require("crypto");
const airgap = require("../../../../checks/register-airgap.js");

let pass = 0, fail = 0;
const tests = [];

function test(name, fn) {
  try {
    fn();
    console.log("PASS", name);
    pass++;
  } catch (e) {
    console.log("FAIL", name, e.message);
    fail++;
  }
}

// Generate real keys/signatures for testing
const { publicKey: edPub, privateKey: edPriv } = crypto.generateKeyPairSync("ed25519");
const edPem = edPub.export({ type: "spki", format: "pem" });
const { publicKey: ecPub, privateKey: ecPriv } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const ecPem = ecPub.export({ type: "spki", format: "pem" });
const { publicKey: rsaPub, privateKey: rsaPriv } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaPem = rsaPub.export({ type: "spki", format: "pem" });

const goodManifest = { schema_version: "1.0", kind: "release", release: "v0.1.0", files: [{ path: "a.js", sha256: "a".repeat(64) }] };
const goodHash = airgap.sha256Hex(Buffer.from(airgap.canonicalize(goodManifest), "utf8"));
const edSig = crypto.sign(null, Buffer.from(goodHash, "utf8"), edPriv).toString("base64");
const goodSignature = { schema_version: "1.0", algo: "ed25519", signer: "maintainer-1", manifest_sha256: goodHash, value: edSig, delivery: "out-of-band" };

// Tests begin
tests.push(() => test("genuine ed25519 signature verifies", () => {
  const res = airgap.run({ manifest: goodManifest, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "verified") throw new Error("Expected verified, got " + res.status);
}));

tests.push(() => test("forged signature fails", () => {
  const forgedSig = { ...goodSignature, value: "a".repeat(64) };
  const res = airgap.run({ manifest: goodManifest, signature: forgedSig, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("unknown signer -> unavailable", () => {
  const res = airgap.run({ manifest: goodManifest, signature: goodSignature, trustedKeys: {} });
  if (res.status !== "unavailable") throw new Error("Expected unavailable, got " + res.status);
}));

tests.push(() => test("tampered manifest fails", () => {
  const tampered = { ...goodManifest, release: "v9.9.9" };
  const res = airgap.run({ manifest: tampered, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("algorithm confusion (ed25519 key with ecdsa algo) fails", () => {
  const confusedSig = { ...goodSignature, algo: "ecdsa-p256-sha256" };
  const res = airgap.run({ manifest: goodManifest, signature: confusedSig, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("extra signature fields rejected", () => {
  const extraSig = { ...goodSignature, extra: "field" };
  const res = airgap.run({ manifest: goodManifest, signature: extraSig, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("inherited signature fields rejected", () => {
  const inheritedSig = Object.create({ inherited: "field" });
  Object.assign(inheritedSig, goodSignature);
  const res = airgap.run({ manifest: goodManifest, signature: inheritedSig, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("prototype pollution cannot fake matches-disk", () => {
  const pollutedFiles = { "a.js": "a".repeat(64) };
  Object.prototype["b.js"] = "b".repeat(64);
  const res = airgap.run({ 
    manifest: { ...goodManifest, files: [...goodManifest.files, { path: "b.js", sha256: "b".repeat(64) }] }, 
    signature: goodSignature, 
    trustedKeys: { "maintainer-1": edPem },
    files: pollutedFiles
  });
  delete Object.prototype["b.js"];
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("malformed input (BigInt) fails closed", () => {
  const res = airgap.run({ manifest: { num: BigInt(1) }, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("malformed input (circular) fails closed", () => {
  const circular = { a: 1 };
  circular.self = circular;
  const res = airgap.run({ manifest: circular, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("malformed input (hostile getter) fails closed", () => {
  const hostile = {};
  Object.defineProperty(hostile, "boom", { get() { throw new Error("boom"); } });
  const res = airgap.run({ manifest: hostile, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("malformed input (proxy) fails closed", () => {
  const proxy = new Proxy({}, { get() { throw new Error("proxy trap"); } });
  const res = airgap.run({ manifest: proxy, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("wrong key type for algo fails", () => {
  const res = airgap.run({ manifest: goodManifest, signature: goodSignature, trustedKeys: { "maintainer-1": rsaPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("invalid base64 signature fails", () => {
  const badSig = { ...goodSignature, value: "not base64!" };
  const res = airgap.run({ manifest: goodManifest, signature: badSig, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("empty manifest fails", () => {
  const res = airgap.run({ manifest: {}, signature: goodSignature, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("null context -> failed", () => {
  const res = airgap.run(null);
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("undefined context -> failed", () => {
  const res = airgap.run(undefined);
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("non-object context -> failed", () => {
  const res = airgap.run("not an object");
  if (res.status !== "failed") throw new Error("Expected failed, got " + res.status);
}));

tests.push(() => test("null signature -> not-applicable", () => {
  const res = airgap.run({ manifest: goodManifest, signature: null, trustedKeys: { "maintainer-1": edPem } });
  if (res.status !== "not-applicable") throw new Error("Expected not-applicable, got " + res.status);
}));

// Run all tests
tests.forEach(t => t());

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
process.exitCode = fail === 0 ? 0 : 1;
