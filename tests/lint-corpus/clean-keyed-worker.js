/* A correctly guarded worker: keyed check-before-write (runId + step). */
const fs = require("fs");
const path = require("path");
const readLines = (p) => (fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\n").filter(Boolean) : []);
module.exports.run = async (input, ctx) => {
  const effects = path.join(ctx.runDir, "effects.log");
  const doneAlready = readLines(effects).includes(ctx.step);
  if (!doneAlready) {
    await mailer.send({ to: input.to, idempotencyKey: `${ctx.runId}:${ctx.step}` });
    fs.appendFileSync(effects, ctx.step + "\n");
  }
  return input;
};
