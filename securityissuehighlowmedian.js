/************************************************************
 INSECURE NODE.JS APPLICATION
 Covers HIGH, MEDIUM, LOW security issues
************************************************************/

const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const cors = require("cors");

const app = express();
app.use(express.json());

// ❌ LOW: Insecure CORS (allows any origin)
app.use(cors({ origin: "*" }));

// ❌ HIGH: Hardcoded secrets
const JWT_SECRET = "super-secret-key";
const DB_PASSWORD = "admin123";

// ❌ HIGH: Database connection without env vars
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "test_db"
});

// ❌ LOW: No security headers (helmet missing)

// --------------------------------------------------
// ❌ HIGH: SQL Injection
app.get("/user", (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, result) => {
    if (err) throw err;
    res.send(result);
  });
});

// --------------------------------------------------
// ❌ HIGH: Authentication bypass + hardcoded password
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (password === "admin123") {
    // ❌ HIGH: Weak JWT (no expiry)
    const token = jwt.sign({ username }, JWT_SECRET);
    res.send({ token });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

// --------------------------------------------------
// ❌ HIGH: JWT decoded without verification
app.get("/profile", (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.decode(token); // ❌ no verify
  res.send(decoded);
});

// --------------------------------------------------
// ❌ HIGH: Remote Code Execution
app.post("/run", (req, res) => {
  const userCode = req.body.code;
  eval(userCode); // 💣 CRITICAL
  res.send("Code executed");
});

// --------------------------------------------------
// ❌ MEDIUM: Cross-Site Scripting (XSS)
app.get("/welcome", (req, res) => {
  res.send(`<h1>Welcome ${req.query.name}</h1>`);
});

// --------------------------------------------------
// ❌ MEDIUM: Open Redirect
app.get("/redirect", (req, res) => {
  res.redirect(req.query.url);
});

// --------------------------------------------------
// ❌ MEDIUM: Missing rate limit (brute force)
app.post("/reset-password", (req, res) => {
  res.send("Password reset link sent");
});

// --------------------------------------------------
// ❌ MEDIUM: CSRF vulnerable endpoint
app.post("/transfer-money", (req, res) => {
  res.send("Money transferred");
});

// --------------------------------------------------
// ❌ HIGH: Insecure file upload
app.post("/upload", (req, res) => {
  const filename = req.query.name;
  fs.writeFileSync(`uploads/${filename}`, req.body.file);
  res.send("File uploaded");
});

// --------------------------------------------------
// ❌ LOW: Sensitive data logging
app.post("/debug", (req, res) => {
  console.log("Password:", req.body.password);
  res.send("Logged");
});

// --------------------------------------------------
// ❌ LOW: Information leakage
app.get("/error", (req, res) => {
  try {
    throw new Error("Something failed");
  } catch (err) {
    res.send(err.stack);
  }
});

// --------------------------------------------------
// ❌ LOW: Weak password validation
function validatePassword(pwd) {
  return pwd.length > 4; // ❌ too weak
}

// --------------------------------------------------
// ❌ LOW: HTTP only (no HTTPS enforcement)
app.listen(3000, () => {
  console.log("Insecure app running on port 3000");
});
