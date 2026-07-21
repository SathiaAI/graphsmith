const openai = require("openai");
async function retry(task) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { return await openai.chat.completions.create(task); } catch {}
  }
  throw new Error("gave up after 3 attempts");
}
