/* Pass E probe (PE-1): a multi-line backtick template is ONE string. Every
 * rule-shaped token below lives INSIDE the template — line 2+ of a template
 * used to be scanned as code and fired a false HIGH R1. Expected: ZERO
 * findings. This file is LLM-reachable (require("openai")). */
const client = require("openai");
const topic = "payments";
const PROMPT = `You are a routing assistant.
Do not write "while (true)" busy loops, and never use for(;;) either.
When Date.now() advances, never use it to pick a branch.
Prefer idempotent, resumable steps for the ${topic} pipeline.
Return one JSON object. Keep going until the task is genuinely done.`;
async function route(task) {
  return client.chat.completions.create({ messages: [{ role: "user", content: PROMPT + task }] });
}
module.exports = { route, PROMPT };
