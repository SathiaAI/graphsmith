/* Pass D probe (PD-6): unbounded LLM work driven by setInterval — no while
 * loop anywhere, must still be R1. */
const { OpenAI } = require("openai");
function start(task) {
  setInterval(async () => {
    await client.chat.completions.create({ messages: [task] });
  }, 1000);
}
module.exports = { start };
