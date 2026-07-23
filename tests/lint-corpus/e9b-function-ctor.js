/* R5 probe: new Function() constructor — must be caught (HIGH). */
module.exports.step = () => {
  return new Function("a", "b", "return a + b");
};
