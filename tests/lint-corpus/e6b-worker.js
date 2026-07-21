/* Worker half of probe E6b — holds the LLM call. */
module.exports.step = async () => {
  return anthropic.messages.create({ model: "claude", messages: [] });
};
