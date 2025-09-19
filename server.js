// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());            // allow http://localhost:5500 etc.
app.use(express.json());    // parse JSON bodies

// 🚧 Demo user store (in-memory). Swap for a DB in production.
const users = new Map(); // username -> { passwordHash }

// Register (demo)
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
    if (users.has(username)) return res.status(409).json({ error: "User already exists" });
    const passwordHash = await bcrypt.hash(password, 10);
    users.set(username, { passwordHash });
    return res.status(201).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const u = users.get(username);
    if (!u) return res.status(401).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ sub: username }, process.env.JWT_SECRET, { expiresIn: "1h" });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
});

// Protected example
app.get("/api/me", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return res.json({ username: payload.sub });
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
