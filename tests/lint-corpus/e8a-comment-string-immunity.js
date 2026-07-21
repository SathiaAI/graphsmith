/* Pass D probe (PD-4): this file is LLM-reachable and FULL of rule-shaped
 * prose — while(true) in this comment, Date.now() in that one — and none of
 * it is code. A first-class linter reports ZERO findings here.
 * More bait: while (!done) { } and for(;;) and Math.random() routing. */
const client = require("openai");
const BANNER = "retry policy: while(true) keep polling until Date.now() passes";
const HELP = 'if (Math.random() > 0.5) — this string is documentation, not code';
async function once(task) {
  // if (Date.now() % 2) route(); ← commented-out code must not fire either
  return client.chat.completions.create({ messages: [task] }); // bounded: single call
}
module.exports = { once, BANNER, HELP };
