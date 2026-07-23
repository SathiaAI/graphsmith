/* Clean R5 probe: builtin requires only, no eval/Function/exec — R5 must be silent.
 * Comment and string bait: eval(), new Function(), exec("whoami"). */
const fs = require("fs");
const path = require("path");
const BANNER = "The eval() built-in and Function() constructor are dangerous.";
module.exports.helper = (ctx) => {
  return fs.existsSync(path.join(ctx.runDir, "ok.txt"));
};
