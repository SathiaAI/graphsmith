/* Council probe E6 (PA-5): loop in manager, LLM in worker — structurally
 * invisible to v0.1.0's per-file scan. The exact split GraphSmith promotes. */
const worker = require("./e6b-worker");
async function main() {
  while (true) {
    await worker.step();
  }
}
main();
