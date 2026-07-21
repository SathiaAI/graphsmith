/* Council probe E6 (PA-5): while(!done) with LLM, no cap — v0.1.0 missed it. */
const { OpenAI } = require("openai");
async function solve(task) {
  let done = false;
  while (!done) {
    const r = await client.chat.completions.create({ messages: [task] });
    done = r.choices[0].finish_reason === "stop";
  }
}
module.exports = { solve };
