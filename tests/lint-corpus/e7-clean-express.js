/* Council probe E7 (PA-6): clean web handler — must produce NO MEDIUM+ noise. */
const express = require("express");
const app = express();
app.get("/users/:id", async (req, res) => {
  const user = await db.users.findOne(req.params.id);
  res.send(user);
});
app.get("/health", async (req, res) => {
  const upstream = await fetch("https://status.example.com/ping");
  res.json({ ok: upstream.ok });
});
app.post("/notes", async (req, res) => {
  const note = await db.notes.create({ body: req.body.text });
  res.status(201).json(note);
});
module.exports = app;
