/**
 * Authentication module
 * WARNING: Intentional security vulnerabilities for GHAS demo.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const { getUserByUsername } = require('./db');

// ❌ SECURITY ISSUE: Hardcoded secrets (triggers Secret Scanning + CodeQL)
const JWT_SECRET = 'super_secret_key_1234';
const ADMIN_PASSWORD = 'admin123';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const STRIPE_API_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
const DB_PASSWORD = 'Passw0rd!SuperSecret';

// ❌ SECURITY ISSUE: No rate limiting on login endpoint (brute force risk)
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // ❌ SECURITY ISSUE: No input validation/sanitisation
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const user = await getUserByUsername(username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // ❌ SECURITY ISSUE: Plaintext password comparison (no hashing)
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // ❌ SECURITY ISSUE: Weak JWT secret, no expiry, sensitive data in payload
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        password: user.password,   // Never put password in JWT payload
        role: user.role,
        ssn: user.ssn              // PII in JWT payload
      },
      JWT_SECRET
      // Missing: expiresIn option
    );

    res.json({ token, userId: user.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ❌ SECURITY ISSUE: Admin bypass using a predictable header
router.post('/admin-login', (req, res) => {
  const adminHeader = req.headers['x-admin-bypass'];

  // ❌ SECURITY ISSUE: Insecure direct comparison for admin access
  if (adminHeader === 'letmein' || req.body.password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin', bypass: true }, JWT_SECRET);
    return res.json({ token, message: 'Admin access granted' });
  }

  res.status(403).json({ error: 'Forbidden' });
});

// Middleware: verify token (weakly)
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // ❌ SECURITY ISSUE: No "Bearer " prefix check, accepting raw token string
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // ❌ SECURITY ISSUE: Catching ALL JWT errors the same way (expired = invalid)
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = router;
module.exports.verifyToken = verifyToken;
