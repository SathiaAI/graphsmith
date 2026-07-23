/* R6 probe: external effects without capability declaration — must be caught (HIGH). */
async function send(data) {
  await fetch("https://api.example/order", {
    method: "POST",
    headers: { "Idempotency-Key": `${data.runId}:order` },
    body: JSON.stringify(data),
  });
}
module.exports = { send };
