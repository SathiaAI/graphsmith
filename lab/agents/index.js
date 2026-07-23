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
 * CLI name+version, provider, model ID+version string, platform.
 * Missing required fields are recorded as null and collected in a 'missing' array.
 * Returns complete: boolean to indicate if all required fields are present. */
function createAttestation(adapterId, opts) {
  opts = opts || {};
  const adapter = ADAPTERS[adapterId];

  if (!adapter) {
    throw new Error(`Unknown adapter: ${adapterId}`);
  }

  /* Required fields (per Contract 12 §Attestation). */
  const requiredFields = ["cli_name", "cli_version", "provider", "model_id", "model_version", "platform"];
  const missing = [];

  /* Record fields that were given; mark missing required fields as null. */
  const attestation = {
    adapter_id: adapterId,
    adapter_name: adapter.name,
    cli_name: adapter.cliName,
    cli_version: opts.cliVersion || null,
    provider: adapter.provider,
    model_id: opts.modelId || null,
    model_version: opts.modelVersion || null,
    platform: opts.platform || null,
  };

  /* Collect missing required fields. */
  if (!opts.cliVersion) {
    missing.push("cli_version");
  }
  if (!opts.modelId) {
    missing.push("model_id");
  }
  if (!opts.modelVersion) {
    missing.push("model_version");
  }
  if (!opts.platform) {
    missing.push("platform");
  }

  attestation.complete = missing.length === 0;
  attestation.missing = missing;

  return attestation;
}

/* Headless mode check. Contract 12: "No headless mode → 'unavailable,'
 * never green" (item 7).
 * If adapter.supportsHeadlessMode === false, the entire cell is unavailable,
 * regardless of isHeadlessMode argument. */
function validateHeadlessMode(adapterId, isHeadlessMode) {
  const adapter = ADAPTERS[adapterId];

  if (!adapter) {
    return { valid: false, reason: "Unknown adapter" };
  }

  /* If the adapter doesn't support headless mode at all, the cell is unavailable. */
  if (!adapter.supportsHeadlessMode) {
    return {
      valid: false,
      reason: `${adapter.name} does not support headless mode`,
      scoreAs: "unavailable",
    };
  }

  /* If the adapter supports headless and we're using headless, all is valid. */
  if (isHeadlessMode && adapter.supportsHeadlessMode) {
    return { valid: true };
  }

  /* If not using headless or headless is not an option, valid. */
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

  try {
    const attestation = createAttestation(adapterId, opts);
    return {
      valid: true,
      adapterId,
      adapterName: adapter.name,
      provider: adapter.provider,
      attestation,
      timeout: opts.timeoutMs || 300000,
      trials: opts.trials || 3,
    };
  } catch (e) {
    return {
      valid: false,
      reason: e.message,
      scoreAs: "unavailable",
    };
  }
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

    /* Test 3: Attestation creation works with all required fields. */
    const att = createAttestation("claude_p", {
      cliVersion: "1.0.0",
      modelId: "claude-3-opus",
      modelVersion: "2024-01",
      platform: "linux",
    });

    if (!att.adapter_id || !att.provider || !att.cli_version || att.cli_version === null) {
      throw new Error("Attestation creation failed");
    }
    if (!att.complete || att.missing.length !== 0) {
      throw new Error("Complete attestation should have complete: true and missing: []");
    }

    /* Test 3b: Attestation marks missing fields without throwing. */
    const attIncomplete = createAttestation("claude_p", { cliVersion: "1.0.0" });
    if (attIncomplete.complete !== false) {
      throw new Error("Incomplete attestation should have complete: false");
    }
    if (!Array.isArray(attIncomplete.missing) || !attIncomplete.missing.includes("model_id")) {
      throw new Error("Missing fields should be tracked in missing array");
    }
    if (attIncomplete.model_id !== null) {
      throw new Error("Missing model_id should be recorded as null");
    }

    /* Test 4: Headless mode validation works. */
    const headlessOk = validateHeadlessMode("opencode", true);
    if (!headlessOk.valid) {
      throw new Error("opencode should support headless mode");
    }

    /* Test 4b: Non-headless adapters are always unavailable (item 7). */
    const headlessFail = validateHeadlessMode("claude_p", false);
    if (headlessFail.valid) {
      throw new Error("claude -p (non-headless adapter) should be unavailable regardless of isHeadlessMode");
    }
    if (headlessFail.scoreAs !== "unavailable") {
      throw new Error("Non-headless adapter should score as 'unavailable'");
    }

    /* Test 5: Cell creation works with headless-supporting adapter. */
    const cell = createCell("opencode", {
      cliVersion: "1.0.0",
      modelId: "deepseek/deepseek-v3",
      modelVersion: "2024-01",
      platform: "linux",
      isHeadlessMode: true,
    });

    if (!cell.valid || !cell.attestation) {
      throw new Error("Cell creation failed");
    }

    /* Test 6: Cell fails with non-headless adapter (item 7). */
    const cellHeadlessFail = createCell("claude_p", {
      cliVersion: "1.0.0",
      modelId: "claude-3-opus",
      modelVersion: "2024-01",
      platform: "linux",
      isHeadlessMode: false,
    });
    if (cellHeadlessFail.valid) {
      throw new Error("Cell should fail with non-headless adapter");
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
