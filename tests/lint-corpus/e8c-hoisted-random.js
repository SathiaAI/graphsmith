/* Pass D probe (PD-15): randomness hoisted far from the branch that routes
 * on it — proximity rules miss this; value tracking must not. */
const client = require("openai");
async function route(task) {
  const roll = Math.random();
  const a = 1;
  const b = 2;
  const c = a + b;
  const d = c * 2;
  const e = d - 1;
  const f = e + a;
  if (roll > 0.5) { return client.chat.completions.create({ messages: [task] }); }
  return "slow-lane";
}
module.exports = { route, };
