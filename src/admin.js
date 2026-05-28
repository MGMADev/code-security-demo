/**
 * Admin module
 * WARNING: Intentional path traversal, SSRF, and command injection vulnerabilities.
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const axios = require('axios');
const { verifyToken } = require('./auth');

// ❌ SECURITY ISSUE: Path traversal — no path normalisation or restriction
// Attacker sends: GET /admin/files?name=../../etc/passwd
router.get('/files', verifyToken, (req, res) => {
  const { name } = req.query;

  // ❌ No path.resolve() check against a safe base directory
  const filePath = path.join(__dirname, '../data/', name);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

// ❌ SECURITY ISSUE: Command injection via exec() with user input
// Attacker sends: POST /admin/ping { "host": "google.com; cat /etc/shadow" }
router.post('/ping', verifyToken, (req, res) => {
  const { host } = req.body;

  // ❌ Never pass user input to exec/spawn without strict allowlisting
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

// ❌ SECURITY ISSUE: SSRF — the server will fetch any URL the attacker provides
// Attacker sends: POST /admin/fetch { "url": "http://169.254.169.254/latest/meta-data/" }
router.post('/fetch', verifyToken, async (req, res) => {
  const { url } = req.body;

  try {
    // ❌ No allowlist, no private IP blocking — exposes cloud metadata endpoints
    const response = await axios.get(url);
    res.json({ data: response.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ❌ SECURITY ISSUE: No role check — any authenticated user can access admin routes
// Should check: if (req.user.role !== 'admin') return res.status(403).json(...)
router.get('/users/export', verifyToken, (req, res) => {
  const { getAllUsers } = require('./db');
  getAllUsers().then(users => {
    // ❌ Dumps all users with PII and credentials
    res.json({ users, exportedAt: new Date().toISOString() });
  });
});

// ❌ SECURITY ISSUE: Regex DoS (ReDoS) — catastrophic backtracking
router.post('/validate-email', (req, res) => {
  const { email } = req.body;
  // This regex has exponential backtracking on certain inputs
  const emailRegex = /^([a-zA-Z0-9_\-\.]+)+@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

module.exports = router;
