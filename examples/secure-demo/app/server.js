const express = require("express");
const { execFile } = require("child_process");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const pattern = /^[a-z0-9.-]+$/;
const match = pattern.exec("example.com");

app.get("/greet", (req, res) => {
  res.type("text/plain").send(`Hello ${String(req.query.name || "")}`);
});

app.get("/lookup", (req, res) => {
  const domain = String(req.query.domain || "");
  if (!pattern.test(domain)) return res.status(400).end();
  execFile("nslookup", [domain], (err, stdout) => res.type("text/plain").send(stdout));
});

app.get("/session", (req, res) => {
  const claims = jwt.verify(req.headers.authorization, process.env.JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
  res.json(claims);
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "internal error" });
});

app.listen(3000);
