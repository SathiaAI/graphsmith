/* R5 probe: eval() call — must be caught (HIGH). */
module.exports.step = (input) => {
  return eval(`(${input.expr})`);
};
