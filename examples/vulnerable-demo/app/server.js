// Intentionally vulnerable Express demo. Fictitious data only. DO NOT DEPLOY.
const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
});

app.get("/lookup", (req, res) => {
  exec(`nslookup ${req.query.domain}`, (err, stdout) => res.send(stdout));
});

app.put("/profile/:id", async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);
  await user.save();
  res.json(user);
});

app.get("/session", (req, res) => {
  const claims = jwt.decode(req.headers.authorization);
  res.json(claims);
});

app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

app.listen(3000);
