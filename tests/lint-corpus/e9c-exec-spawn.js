/* R5 probe: child_process exec — must be caught (HIGH). */
const { exec } = require("child_process");
module.exports.step = () => {
  exec("echo done");
};
