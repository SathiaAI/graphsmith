/* GSA MCP attestation shim — scripts/gsa-mcp-shim.js.
 * Maps a captured MCP (JSON-RPC) session into a GSA *boundary* attestation bundle: it observes the
 * MCP boundary (tool I/O), not the agent's internal plan, so it earns a labeled LESSER claim —
 * profile A only (boundary), never the full plan profiles. "Any MCP agent, no agent changes."
 *
 * Honesty (design §5/§6): a boundary bundle records which tools were called, with what inputs and
 * results, against what granted surface, and that the record is unaltered — NOT the agent's plan
 * (never emitted), NOT non-MCP side effects, NOT model internals. The plan artifacts are honest
 * placeholders marked boundary-only; the bundle asserts profile A and nothing it did not observe.
 * Reuses gsa-produce (single-source sealing). Zero-dep CJS, Node >= 18.
 *
 * NOTE: v0.3.0 labels the boundary tier via producer + decision_record + an A-only profile set. A
 * dedicated boundary sub-profile in the schema is the next increment (SPEC-CHANGES [Unreleased]).
 */
"use strict";
const crypto = require("crypto");
const { produceBundle } = require("./gsa-produce.js");

function sha256Hex(s) { return crypto.createHash("sha256").update(Buffer.from(String(s), "utf8")).digest("hex"); }

/* session = {
 *   initialize: { clientInfo:{name,version}, serverInfo:{name,version}, model?:string },
 *   tools:      [{ name, server, schema }],            // from tools/list — the GRANTED surface
 *   calls:      [{ tool, arguments, result, isError?, model_call?, ts? }],  // tools/call sequence
 *   goal?:      string
 * }
 * keys = { privateKey, signer, algo } */
function sealBoundaryBundle(session, keys) {
  if (!session || typeof session !== "object") throw new Error("sealBoundaryBundle: session required");
  const init = session.initialize || {};
  const tools = Array.isArray(session.tools) ? session.tools : [];
  const calls = Array.isArray(session.calls) ? session.calls : [];

  const grantedTools = tools.map((t) => (t.server ? t.server + ":" : "") + t.name);
  // execution_trace: one entry per tool call; a call to a tool NOT in the granted surface is flagged.
  const traceLines = calls.map((c, i) => {
    const id = (c.server ? c.server + ":" : "") + c.tool;
    return JSON.stringify({
      step: i + 1, kind: "mcp_tool_call", tool: id,
      granted: grantedTools.indexOf(id) !== -1,          // requested ⊆ granted signal
      input_sha256: sha256Hex(JSON.stringify(c.arguments === undefined ? null : c.arguments)),
      result_sha256: sha256Hex(JSON.stringify(c.result === undefined ? null : c.result)),
      is_error: !!c.isError,
      model_call: !!c.model_call,                        // sampling/createMessage → non-deterministic
    });
  });
  const outputs = calls.filter((c) => !c.isError).map((c, i) => ({ call: i + 1, result_sha256: sha256Hex(JSON.stringify(c.result === undefined ? null : c.result)) }));

  const BOUNDARY = "boundary-only: the MCP shim observes tool I/O, not the agent's plan. Not emitted by the agent.";
  const A = (path, body) => ({ path, body });
  const run = {
    bundle_id: "gsa-" + sha256Hex(JSON.stringify({ init, grantedTools, n: calls.length })).slice(0, 16),
    mode: "standard",
    profiles: ["A"],                                     // boundary tier earns A only, never full profiles
    producer: { name: "gsa-mcp-shim", version: "0.3.0" },
    artifacts: {
      goal: A("goal.txt", String(session.goal || "MCP boundary attestation")),
      policy: A("policy.yaml", "attestation_tier: boundary\ngranted_tools:\n" + grantedTools.map((t) => "  - " + t).join("\n")),
      model_manifest: A("model_manifest.json", JSON.stringify({ model: init.model || "unavailable", client: init.clientInfo || null, server: init.serverInfo || null })),
      generated_ir: A("generated_ir.json", JSON.stringify({ boundary: BOUNDARY })),
      compiled_graph: A("compiled_graph.json", JSON.stringify({ boundary: BOUNDARY })),
      validation_report: A("validation_report.json", JSON.stringify({ boundary: BOUNDARY })),
      execution_trace: A("execution_trace.jsonl", traceLines.join("\n")),
      output_manifest: A("output_manifest.json", JSON.stringify({ outputs })),
      decision_record: A("decision_record.md", "# MCP boundary attestation\n\nTool I/O at the MCP boundary only. The agent's plan/compiled graph was not observed (no agent changes were made). Non-MCP side effects are NOT captured. This bundle asserts profile A (boundary), never the full plan profiles."),
    },
    // Each MCP tool becomes a skill entry with provenance = hash of its declared schema. MCP tools are
    // observed, not GraphSmith-approved — so all_skills_signed_and_approved honestly recomputes false.
    skills: tools.map((t) => ({ skill_id: (t.server ? t.server + ":" : "") + t.name, version: (t.version || "unavailable"), implementation_hash: sha256Hex(JSON.stringify(t.schema || t.name)), source: "remote", approval_status: "observed", signature: "" })),
    adversarial: { suites: [] },                         // boundary shim runs no adversarial battery → X not asserted
    capabilities: { result: "observed", resources: { network: { granted: grantedTools } } },
  };
  const bundle = produceBundle(run, keys);
  return { bundle, tier: "boundary", granted_tools: grantedTools, calls: calls.length };
}

module.exports = { sealBoundaryBundle };

if (require.main === module && process.argv.includes("--selftest")) {
  const { verifyBundle } = require("./gsa-verify.js");
  const kp = crypto.generateKeyPairSync("ed25519");
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  // A reference MCP session against a filesystem + web server the shim did NOT build.
  const session = {
    initialize: { clientInfo: { name: "some-agent", version: "2.1" }, serverInfo: { name: "fs-server", version: "0.4" }, model: "gpt-5.6" },
    tools: [{ name: "read_file", server: "fs", schema: { path: "string" } }, { name: "fetch", server: "web", schema: { url: "string" } }],
    calls: [
      { tool: "read_file", server: "fs", arguments: { path: "intake.txt" }, result: { text: "patient form" } },
      { tool: "fetch", server: "web", arguments: { url: "https://api.example/x" }, result: { status: 200 }, model_call: false },
      { tool: "summarise", server: "llm", arguments: { text: "..." }, result: { summary: "ok" }, model_call: true }, // NOT in granted surface
    ],
    goal: "summarise the intake form",
  };
  const keys = { privateKey: kp.privateKey, signer: "shim-key", algo: "ed25519" };
  const { bundle, tier } = sealBoundaryBundle(session, keys);
  const v = verifyBundle(bundle, { trustedKeys: { "shim-key": pem } });
  // Honesty checks: valid boundary bundle PASSes; asserts+confirms A; does NOT confirm full profiles
  // (G/T beyond what it saw); the ungranted tool call is flagged in the trace; skills-approved is false.
  const traceStr = bundle.contents["execution_trace.jsonl"];
  const ungrantedFlagged = /"tool":"llm:summarise","granted":false/.test(traceStr);
  const skillsApproved = bundle.manifest.control_attestations.all_skills_signed_and_approved;
  const pass = v.status === "PASS" && tier === "boundary" &&
    v.confirmed_profiles.length === 1 && v.confirmed_profiles[0] === "A" &&
    ungrantedFlagged === true && skillsApproved === false;
  console.log("gsa-mcp-shim selftest:", pass ? "OK" : "FAIL",
    "| boundary-bundle-verifies=" + (v.status === "PASS"), "confirmed=" + JSON.stringify(v.confirmed_profiles),
    "ungranted-tool-flagged=" + ungrantedFlagged, "mcp-tools-not-approved=" + (skillsApproved === false));
  process.exit(pass ? 0 : 1);
}
