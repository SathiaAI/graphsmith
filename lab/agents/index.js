/* GraphSmith Conformance Lab — Agent Adapter Stubs (lab/agents/index.js)
 * Contract 12: adapter STUBS declaring the cell interface (codex exec · claude -p ·
 * opencode -m openrouter/<model> · cursor-agent) with attestation fields and the
 * "no headless mode → unavailable, never green" rule. Stubs, not live callers.
 * Zero-dep CommonJS, Node >= 18.
 */
"use strict";

const SCHEMA_VERSION = "1.0";

/* Agent adapter cell interfaces. Contract 12 §Cells, attestation:
 * "Adapters: codex exec · claude -p · opencode -m openrouter/<model>
 * (deepseek/qwen/grok/gemini/gpt) · cursor-agent/copilot/gemini-cli as available.
 * No headless mode → 'unavailable,' never green.
 * Attestation: each cell records CLI name+version, provider, model ID+version
 * string, platform — printed in the matrix row." */

const ADAPTERS = {
  claude_p: {
    id: "claude-p",
    name: "claude -p",
    provider: "Anthropic",
    cliName: "claude",
    canDetectVersion: true,
    supportsHeadlessMode: false,
    description: "Claude via claude-cli prompt interface",
    attestationFields: [
      "cli_name",
      "cli_version",
      "provider",
      "model_id",
      "model_version",
      "platform",
    ],
    probeCommand: "claude --version",
  },

  codex_exec: {
    id: "codex-exec",
    name: "codex exec",
    provider: "GitHub Copilot",
    cliName: "codex",
    canDetectVersion: false,
    supportsHeadlessMode: false,
    description: "Codex via exec interface (deprecated, stub for reference)",
    attestationFields: [
      "cli_name",
      "provider",
      "model_id",
      "platform",
    ],
    probeCommand: "codex --version",
  },

  opencode: {
    id: "opencode",
    name: "opencode -m",
    provider: "OpenRouter",
    cliName: "opencode",
    canDetectVersion: true,
    supportsHeadlessMode: true,
    description: "OpenRouter models via opencode interface",
    supportedModels: [
      "deepseek/deepseek-v3",
      "qwen/qwen-2.5-coder-32b",
      "grok/grok-2",
      "google/gemini-2.0-flash",
      "openai/gpt-4-turbo",
    ],
    attestationFields: [
      "cli_name",
      "cli_version",
      "provider",
      "model_id",
      "model_version",
      "platform",
    ],
    probeCommand: "opencode --version",
  },

  cursor_agent: {
    id: "cursor-agent",
    name: "cursor-agent",
    provider: "Cursor",
    cliName: "cursor-agent",
    canDetectVersion: false,
    supportsHeadlessMode: false,
    description: "Cursor agent interface",
    attestationFields: [
      "cli_name",
      "provider",
      "model_id",
      "platform",
    ],
    probeCommand: null,
  },

  gemini_cli: {
    id: "gemini-cli",
    name: "gemini-cli",
    provider: "Google",
    cliName: "gemini",
    canDetectVersion: false,
    supportsHeadlessMode: false,
    description: "Google Gemini CLI interface",
    attestationFields: [
      "cli_name",
      "provider",
      "model_id",
      "platform",
    ],
    probeCommand: "gemini --version",
  },

  copilot: {
    id: "copilot",
    name: "copilot",
    provider: "GitHub",
    cliName: "copilot",
    canDetectVersion: false,
    supportsHeadlessMode: false,
    description: "GitHub Copilot CLI interface",
    attestationFields: [
      "cli_name",
      "provider",
      "model_id",
      "platform",
    ],
    probeCommand: null,
  },
};

/* Cell attestation structure. Contract 12 §Attestation: each cell records
 * CLI name+version, provider, model ID+version string, platform. */
function createAttestation(adapterId, opts) {
  opts = opts || {};
  const adapter = ADAPTERS[adapterId];

  if (!adapter) {
    throw new Error(`Unknown adapter: ${adapterId}`);
  }

  return {
    adapter_id: adapterId,
    adapter_name: adapter.name,
    cli_name: adapter.cliName,
    cli_version: opts.cliVersion || "unknown",
    provider: adapter.provider,
    model_id: opts.modelId || "unknown",
    model_version: opts.modelVersion || "unknown",
    platform: opts.platform || "unknown",
    generated_at: new Date().toISOString(),
  };
}

/* Headless mode check. Contract 12: "No headless mode → 'unavailable,'
 * never green". */
function validateHeadlessMode(adapterId, isHeadlessMode) {
  const adapter = ADAPTERS[adapterId];

  if (!adapter) {
    return { valid: false, reason: "Unknown adapter" };
  }

  if (isHeadlessMode && !adapter.supportsHeadlessMode) {
    return {
      valid: false,
      reason: `${adapter.name} does not support headless mode`,
      scoreAs: "unavailable",
    };
  }

  return { valid: true };
}

/* Cell configuration: combines adapter, attestation, and environment. */
function createCell(adapterId, opts) {
  opts = opts || {};
  const adapter = ADAPTERS[adapterId];

  if (!adapter) {
    throw new Error(`Unknown adapter: ${adapterId}`);
  }

  const headlessCheck = validateHeadlessMode(adapterId, opts.isHeadlessMode);
  if (!headlessCheck.valid) {
    return {
      valid: false,
      reason: headlessCheck.reason,
      scoreAs: headlessCheck.scoreAs,
    };
  }

  return {
    valid: true,
    adapterId,
    adapterName: adapter.name,
    provider: adapter.provider,
    attestation: createAttestation(adapterId, opts),
    timeout: opts.timeoutMs || 300000,
    trials: opts.trials || 3,
  };
}

function getAdapter(adapterId) {
  return ADAPTERS[adapterId] || null;
}

function listAdapters() {
  return Object.keys(ADAPTERS).map((key) => ({
    id: ADAPTERS[key].id,
    name: ADAPTERS[key].name,
    provider: ADAPTERS[key].provider,
    headlessSupported: ADAPTERS[key].supportsHeadlessMode,
  }));
}

function selftest() {
  try {
    /* Test 1: Adapters are defined. */
    if (Object.keys(ADAPTERS).length === 0) {
      throw new Error("No adapters defined");
    }

    /* Test 2: Each adapter has required fields. */
    for (const [key, adapter] of Object.entries(ADAPTERS)) {
      if (!adapter.id || !adapter.name || !adapter.provider) {
        throw new Error(`Adapter ${key} missing required fields`);
      }
    }

    /* Test 3: Attestation creation works. */
    const att = createAttestation("claude_p", {
      cliVersion: "1.0.0",
      modelId: "claude-3-opus",
      modelVersion: "2024-01",
      platform: "linux",
    });

    if (!att.adapter_id || !att.provider) {
      throw new Error("Attestation creation failed");
    }

    /* Test 4: Headless mode validation works. */
    const headlessOk = validateHeadlessMode("opencode", true);
    if (!headlessOk.valid) {
      throw new Error("opencode should support headless mode");
    }

    const headlessFail = validateHeadlessMode("claude_p", true);
    if (headlessFail.valid) {
      throw new Error("claude -p should not support headless mode");
    }
    if (headlessFail.scoreAs !== "unavailable") {
      throw new Error("Headless unsupported should score as 'unavailable'");
    }

    /* Test 5: Cell creation works. */
    const cell = createCell("claude_p", {
      cliVersion: "1.0.0",
      modelId: "claude-3-opus",
      isHeadlessMode: false,
    });

    if (!cell.valid || !cell.attestation) {
      throw new Error("Cell creation failed");
    }

    /* Test 6: Cell fails gracefully with headless mode unsupported. */
    const cellHeadlessFail = createCell("claude_p", { isHeadlessMode: true });
    if (cellHeadlessFail.valid) {
      throw new Error("Cell should fail with headless mode unsupported");
    }
    if (cellHeadlessFail.scoreAs !== "unavailable") {
      throw new Error("Cell failure should score as 'unavailable'");
    }

    /* Test 7: getAdapter works. */
    const adapter = getAdapter("claude_p");
    if (!adapter || adapter.name !== "claude -p") {
      throw new Error("getAdapter failed");
    }

    /* Test 8: listAdapters works. */
    const adapters = listAdapters();
    if (adapters.length === 0) {
      throw new Error("listAdapters returned empty");
    }

    console.log("✓ lab/agents/index.js --selftest PASSED");
    return 0;
  } catch (e) {
    console.error("✗ lab/agents/index.js --selftest FAILED:", e.message);
    return 1;
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes("--selftest")) {
    process.exit(selftest());
  }
  console.log(JSON.stringify({ adapters: listAdapters() }, null, 2));
}

module.exports = {
  ADAPTERS,
  createAttestation,
  validateHeadlessMode,
  createCell,
  getAdapter,
  listAdapters,
  SCHEMA_VERSION,
};
