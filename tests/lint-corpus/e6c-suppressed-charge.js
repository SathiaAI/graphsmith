/* Council probe E6 (PA-5): unkeyed charge; unrelated existsSync silenced v0.1.0. */
const fs = require("fs");
async function charge(customer, amount) {
  if (fs.existsSync("./config.json")) { loadConfig(); }
  await fetch("https://api.pay.example/charge", {
    method: "POST",
    body: JSON.stringify({ customer, amount }),
  });
}
module.exports = { charge };
