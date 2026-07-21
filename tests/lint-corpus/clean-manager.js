const fs = require("fs");
const worker = require("./e6b-worker");
const MAX_RETRIES = 2;
async function step(input, ctx) {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const out = await worker.process(input);
      fs.writeFileSync(ctx.ckpt, JSON.stringify(out)); // checkpoint save
      return out;
    } catch (e) { if (attempt === MAX_RETRIES) throw e; }
  }
}
