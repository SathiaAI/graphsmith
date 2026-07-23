/* R5 probe: non-builtin external require — must be caught (REVIEW). */
const pkg = require("unused-external-package");
const { step } = require("some-new-module");
module.exports.step = () => step(pkg);
