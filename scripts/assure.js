#!/usr/bin/env node
/* GraphSmith assure.js — v0.2.0 MINIMAL evidence packet orchestrator (§17).
 *
 * Orchestrates: test + lint (graphlint) + redteam + registered external tools.
 * Emits a MINIMAL evidence packet stub. Full packet format is Phase E —
 * this packet is honest about what is stubbed.
 *
 * Not a certification. A passing packet is a FLOOR of harness evidence.
 * Banned claim language (contract 10) is self-checked.
 *
 * Zero-dep CJS, Node ≥ 18. JSON stdout / prose stderr; exit 0/1/2.
 * Usage:
 *   node scripts/assure.js <project-dir> [--tools <registry.json>] [--byo <path>]
 *   node scripts/assure.js --selftest
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const SCHEMA_VERSION = "0.2.0-minimal";
const ASSURE_VERSION = "0.2.0";
const REPO_ROOT = path.resolve(__dirname, "..");

const testMod = require(path.join(__dirname, "test.js"));
const redteamMod = require(path.join(__dirname, "redteam.js"));
const extRunner = require(path.join(__dirname, "ext-tool-runner.js"));

const err = (msg) => process.stderr.write(msg + "\n");
const out = (obj) => process.stdout.write(JSON.stringify(obj, null, 2) + "\n");

function sha256(data) {
  return crypto
    .createHash("sha256")
    .update(typeof data === "string" || Buffer.isBuffer(data) ? data : JSON.stringify(data))
    .digest("hex");
}

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith("--")) {
      const key = k.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) a[key] = argv[++i];
      else a[key] = true;
    } else a._.push(k);
  }
  return a;
}

function toolVersions() {
  const versions = {
    assure: ASSURE_VERSION,
    test: testMod.TEST_VERSION,
    redteam: redteamMod.REDTEAM_VERSION,
    ext_tool_runner: extRunner.RUNNER_VERSION,
    node: process.versions.node,
  };
  const lintPath = path.join(__dirname, "graphlint.js");
  versions.graphlint = fs.existsSync(lintPath) ? "present" : "absent";
  return versions;
}

function runLint(projectDir) {
  const lintPath = path.join(__dirname, "graphlint.js");
  if (!fs.existsSync(lintPath)) {
    return {
      component: "lint",
      status: "unavailable",
      reason: "graphlint.js_absent",
      findings_count: null,
    };
  }
  const r = spawnSync(process.execPath, [lintPath, path.resolve(projectDir)], {
    encoding: "utf8",
    timeout: 60000,
    windowsHide: true,
  });
  const text = (r.stdout || "") + (r.stderr || "");
  /* Parse severity markers as evidence DATA; status from presence of HIGH/MEDIUM. */
  const high = (text.match(/\[HIGH\]/g) || []).length;
  const medium = (text.match(/\[MEDIUM\]/g) || []).length;
  const review = (text.match(/\[REVIEW\]/g) || []).length;
  const clean =
    /no violations flagged/i.test(text) || (high === 0 && medium === 0 && r.status === 0);
  return {
    component: "lint",
    status: r.error ? "error" : clean ? "pass" : high + medium > 0 ? "fail" : "pass",
    exit_code: r.status,
    findings_count: { high, medium, review },
    stdout_excerpt: (r.stdout || "").slice(0, 800),
    note: "Heuristic architectural discipline scan. Absence of findings is not proof of correctness.",
  };
}

/**
 * Build minimal evidence packet (Phase E will expand).
 * Honest stubs called out explicitly.
 */
function buildPacket(opts) {
  const projectDir = path.resolve(opts.projectDir || ".");
  const generatedAt = new Date().toISOString(); /* metadata only */

  err("assure: running test battery…");
  const testReport = testMod.runSuite(projectDir, {
    includeScenario: opts.includeScenario !== false,
    chaos: !!opts.chaos,
    smokeRunId: opts.smokeRunId || "assure-smoke-1",
  });

  err("assure: running lint…");
  const lintReport = runLint(projectDir);

  err("assure: running architecture adversarial battery…");
  const redteamReport = redteamMod.runRedteam({
    project: projectDir,
    byo: opts.byo,
    deepCorpus: !!opts.deepCorpus,
  });

  err("assure: running external tools (if registered)…");
  let toolsReport = {
    schema_version: extRunner.SCHEMA_VERSION,
    runner_version: extRunner.RUNNER_VERSION,
    counts: { pass: 0, fail: 0, unavailable: 0, error: 0, skip: 0, total: 0 },
    results: [],
  };
  if (opts.tools) {
    const specs = extRunner.loadRegistryFile(path.resolve(opts.tools));
    toolsReport = extRunner.runRegistry(specs, { seedDir: projectDir });
  }

  const batteries = [
    {
      name: "test",
      status: testReport.status,
      report_sha256: testReport.report_sha256,
      summary: testReport.summary,
      failed_ids: testReport.failed_ids,
    },
    {
      name: "lint",
      status: lintReport.status,
      findings_count: lintReport.findings_count,
    },
    {
      name: "redteam",
      status: redteamReport.status,
      report_sha256: redteamReport.report_sha256,
      summary: redteamReport.summary,
      failed_ids: redteamReport.failed_ids,
      scope: redteamReport.scope,
    },
  ];

  /* Q = assurance-tested floor: test pass + lint not fail
   * X = adversarially-tested floor: redteam pass
   * Attestation here is of battery outcomes only — not a security claim. */
  const qEligible =
    testReport.status === "pass" &&
    (lintReport.status === "pass" || lintReport.status === "unavailable");
  const xEligible = redteamReport.status === "pass";

  const packet = {
    schema_version: SCHEMA_VERSION,
    packet_kind: "minimal_stub",
    component: "assure",
    version: ASSURE_VERSION,
    stub: true,
    stub_notes: [
      "Full evidence-packet format, deep sign-off/retention, and badge wiring are Phase E.",
      "log_ref.anchored_head is null in the minimal stub (no adoption-log walk here).",
      "capability_profile_attestation records battery outcomes only — not a certification.",
    ],
    honest_scope: {
      statement:
        "GraphSmith is an assurance harness, orchestration, and evidence layer plus a reliability/discipline attack corpus. A passing battery is a floor, not proof of security or correctness. Security judgment stays with humans and dedicated tools.",
      not:
        "architecture-level adversarial battery is not a model-jailbreak suite; external engines plug in via exit-code+JSON-report",
    },
    project: projectDir,
    platform: {
      os: process.platform,
      arch: process.arch,
      node: process.versions.node,
    },
    tool_versions: toolVersions(),
    timestamps: {
      generated_at: generatedAt,
    },
    log_ref: {
      kind: "tamper-evident-vs-anchored-head",
      anchored_head: null,
      stub: true,
      note: "Phase E wires rewrite-detecting chain walk vs project adoption-log head",
    },
    capability_profile_attestation: {
      Q_assurance_tested: {
        eligible: qEligible,
        basis: "test battery pass + lint not fail",
        evidence_batteries: ["test", "lint"],
      },
      X_adversarially_tested: {
        eligible: xEligible,
        basis: "architecture adversarial battery pass",
        evidence_batteries: ["redteam"],
        does_not_include: "model_level_jailbreak",
      },
      stub: true,
    },
    batteries,
    external_tools: {
      registry: opts.tools ? path.resolve(opts.tools) : null,
      counts: toolsReport.counts,
      results: toolsReport.results.map((r) => ({
        id: r.id,
        status: r.status,
        executed: r.executed,
        reason: r.reason || null,
        report_sha256: r.report_sha256 || null,
        container_required: r.container_required,
        /* opaque_data included as DATA for human review; not used for packet status */
        opaque_data: r.opaque_data || null,
      })),
    },
    /* Full reports nested for claim→run linkage (minimal). */
    evidence: {
      test: testReport,
      lint: lintReport,
      redteam: redteamReport,
    },
    status: null,
    packet_sha256: null,
  };

  /* Packet status: fail if any core battery failed; external unavailable is ok. */
  const coreFail = batteries.some((b) => b.status === "fail" || b.status === "error");
  const toolFail = (toolsReport.results || []).some(
    (r) => r.status === "fail" || r.status === "error"
  );
  packet.status = coreFail || toolFail ? "fail" : "pass";

  packet.packet_sha256 = sha256(
    JSON.stringify({
      schema_version: packet.schema_version,
      project: packet.project,
      batteries: packet.batteries,
      external_tools: {
        counts: packet.external_tools.counts,
        results: packet.external_tools.results.map((r) => ({
          id: r.id,
          status: r.status,
          report_sha256: r.report_sha256,
        })),
      },
      status: packet.status,
    })
  );

  return packet;
}

function scanBanned(text) {
  const res = [
    /\bpen[\s-]?test\b/i,
    /\bcertified\s+secure\b/i,
    /\bsecurity\s+guaranteed\b/i,
  ];
  return res.filter((re) => re.test(String(text || ""))).map((re) => re.source);
}

function selftest() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gs-assure-self-"));
  const checks = [];
  try {
    /* Build a good mini workflow fixture via test.js conventions. */
    const proj = path.join(tmp, "wf");
    /* reuse test module fixture writer indirectly by writing same shape */
    fs.mkdirSync(path.join(proj, "workers"), { recursive: true });
    fs.writeFileSync(
      path.join(proj, "pipeline.json"),
      JSON.stringify(
        [
          { step: "01-collect", worker: "collect.js" },
          { step: "02-process", worker: "process.js" },
        ],
        null,
        2
      )
    );
    const w = [
      '"use strict";',
      'const fs=require("fs");const path=require("path");',
      "function ad(f,l){const fd=fs.openSync(f,\"a\");try{fs.writeSync(fd,l+\"\\n\");fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}",
      "const rl=p=>fs.existsSync(p)?fs.readFileSync(p,\"utf8\").split(\"\\n\").filter(Boolean):[];",
      "module.exports.run=async(input,ctx)=>{",
      "const I=path.join(ctx.runDir,\"intents.log\"),E=path.join(ctx.runDir,\"effects.log\");",
      "if(rl(E).indexOf(ctx.step)!==-1)return input||{};",
      "if(rl(I).indexOf(ctx.step)!==-1){const e=new Error(\"UNRESOLVED SIDE EFFECT\");e.unresolvedSideEffect=true;throw e;}",
      "ad(I,ctx.step);ad(E,ctx.step);return Object.assign({},input||{},{ok:true});};",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(proj, "workers", "collect.js"), w);
    fs.writeFileSync(path.join(proj, "workers", "process.js"), w);
    fs.writeFileSync(
      path.join(proj, "manager.js"),
      [
        '"use strict";',
        'const fs=require("fs");const path=require("path");',
        'const P=JSON.parse(fs.readFileSync(path.join(__dirname,"pipeline.json"),"utf8"));',
        'const runId=process.argv[2]||"default";',
        'const runDir=path.join(__dirname,".runs",runId);',
        "fs.mkdirSync(runDir,{recursive:true});",
        "(async()=>{let input={};",
        "for(const step of P){",
        'const cp=path.join(runDir,step.step+".json");',
        'if(fs.existsSync(cp)){input=JSON.parse(fs.readFileSync(cp,"utf8")).output;process.stdout.write(JSON.stringify({step:step.step,status:"skipped"})+"\\n");continue;}',
        'const wName=step.worker.endsWith(".js")?step.worker:step.worker+".js";',
        'const worker=require(path.join(__dirname,"workers",wName));',
        "const output=await worker.run(input,{runId,step:step.step,runDir});",
        'fs.writeFileSync(cp,JSON.stringify({step:step.step,status:"ok",output},null,2));',
        'process.stdout.write(JSON.stringify({step:step.step,status:"ok"})+"\\n");input=output;}',
        'process.stdout.write("__done__\\n");',
        "})().catch(e=>{console.error(e.message||e);process.exit(1);});",
        "",
      ].join("\n")
    );

    /* External tool registry: one trusted standard-profile tool (not BYO). */
    const toolJs = path.join(tmp, "ext-ok.js");
    fs.writeFileSync(
      toolJs,
      'console.log(JSON.stringify({schema_version:"1.0",status:"pass",summary:"fixture tool"}));\n'
    );
    const reg = path.join(tmp, "tools.json");
    fs.writeFileSync(
      reg,
      JSON.stringify(
        [
          {
            id: "fixture-tool",
            command: process.execPath,
            args: [toolJs],
            untrusted: false,
            external: false,
            requires_container: false,
          },
        ],
        null,
        2
      )
    );

    /* BYO malicious for packet path — should show unavailable external. */
    const evil = path.join(tmp, "evil.js");
    fs.writeFileSync(
      evil,
      'console.log(JSON.stringify({status:"pass",summary:"should not run"}));\n'
    );
    const byo = path.join(tmp, "byo-evil.json");
    fs.writeFileSync(
      byo,
      JSON.stringify({
        id: "evil",
        kind: "executable",
        byo: true,
        command: process.execPath,
        args: [evil],
      })
    );

    const packet = buildPacket({
      projectDir: proj,
      tools: reg,
      byo: byo,
      includeScenario: false, /* keep selftest fast + offline from heavy scenario */
      smokeRunId: "assure-self-1",
    });

    checks.push({
      id: "self.packet-emitted",
      status: packet && packet.schema_version === SCHEMA_VERSION ? "pass" : "fail",
      evidence: { schema_version: packet && packet.schema_version },
    });
    checks.push({
      id: "self.stub-honest",
      status: packet.stub === true && Array.isArray(packet.stub_notes) ? "pass" : "fail",
      evidence: { stub: packet.stub },
    });
    checks.push({
      id: "self.has-battery",
      status:
        Array.isArray(packet.batteries) && packet.batteries.length >= 1 ? "pass" : "fail",
      evidence: {
        names: (packet.batteries || []).map((b) => b.name),
        count: (packet.batteries || []).length,
      },
    });
    checks.push({
      id: "self.has-external-tool-result",
      status:
        packet.external_tools &&
        packet.external_tools.results &&
        packet.external_tools.results.length >= 1
          ? "pass"
          : "fail",
      evidence: { results: packet.external_tools && packet.external_tools.results },
    });
    checks.push({
      id: "self.log-ref-stub",
      status:
        packet.log_ref &&
        packet.log_ref.kind === "tamper-evident-vs-anchored-head" &&
        packet.log_ref.stub === true
          ? "pass"
          : "fail",
      evidence: packet.log_ref,
    });
    checks.push({
      id: "self.byo-contained-in-redteam",
      status:
        packet.evidence &&
        packet.evidence.redteam &&
        packet.evidence.redteam.checks.some(
          (c) => c.id === "byo.exec.evil" && c.status === "unavailable"
        )
          ? "pass"
          : "fail",
      evidence: {
        redteam_status: packet.evidence && packet.evidence.redteam && packet.evidence.redteam.status,
      },
    });

    const bannedHits = scanBanned(JSON.stringify(packet));
    checks.push({
      id: "self.honest-scope",
      status: bannedHits.length === 0 ? "pass" : "fail",
      evidence: { hits: bannedHits },
    });

    const failed = checks.filter((c) => c.status !== "pass");
    const result = {
      schema_version: SCHEMA_VERSION,
      component: "assure",
      version: ASSURE_VERSION,
      status: failed.length === 0 ? "pass" : "fail",
      checks,
      failed: failed.map((c) => c.id),
      packet_status: packet.status,
      packet_sha256: packet.packet_sha256,
      batteries: packet.batteries.map((b) => ({ name: b.name, status: b.status })),
    };
    out(result);
    if (failed.length) {
      err("selftest: FAIL (" + failed.map((c) => c.id).join(", ") + ")");
      process.exit(1);
    }
    err("selftest: PASS (" + checks.length + " checks)");
  } finally {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch (_) {}
  }
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.selftest) {
    selftest();
    return;
  }
  const project = args._[0] || args.project;
  if (!project) {
    err(
      "Usage:\n" +
        "  node scripts/assure.js <project-dir> [--tools <registry.json>] [--byo <path>] [--chaos] [--deep-corpus]\n" +
        "  node scripts/assure.js --selftest\n"
    );
    process.exit(2);
  }
  if (!fs.existsSync(path.resolve(project))) {
    err("ERR: project dir not found: " + project);
    process.exit(2);
  }
  const packet = buildPacket({
    projectDir: project,
    tools: args.tools,
    byo: args.byo,
    chaos: !!args.chaos,
    deepCorpus: !!(args["deep-corpus"] || args.deep),
    includeScenario: !args["no-scenario"],
  });
  out(packet);
  process.exit(packet.status === "pass" ? 0 : 1);
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = {
  SCHEMA_VERSION,
  ASSURE_VERSION,
  buildPacket,
  runLint,
  selftest,
};
