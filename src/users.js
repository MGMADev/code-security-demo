/**
 * Users router
 * WARNING: Intentional IDOR, mass assignment, and injection vulnerabilities.
 */

const express = require('express');
const router = express.Router();
const { getUserById, getAllUsers, searchProducts, db } = require('./db');
const { verifyToken } = require('./auth');

// ❌ SECURITY ISSUE: No authentication required to list all users
// Should require verifyToken middleware AND admin role check
router.get('/', async (req, res) => {
  try {
    const users = await getAllUsers();
    // ❌ SECURITY ISSUE: Returning sensitive fields (password, ssn, credit_card)
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ❌ SECURITY ISSUE: IDOR — any user can access any other user's profile
// No check that req.user.id === req.params.id
router.get('/:id', verifyToken, async (req, res) => {
  try {
    const user = await getUserById(req.params.id); // also SQL injectable
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user); // ❌ Again returns full row including password, SSN
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ❌ SECURITY ISSUE: Mass assignment — attacker can set role to 'admin'
router.put('/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const updates = req.body; // ❌ Never whitelist fields; attacker sends { "role": "admin" }

  const fields = Object.keys(updates).map(k => `${k} = '${updates[k]}'`).join(', ');

  // ❌ SECURITY ISSUE: SQL injection in UPDATE statement AND mass assignment
  const query = `UPDATE users SET ${fields} WHERE id = ${id}`;

  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'User updated', changes: this.changes });
  });
});

// ❌ SECURITY ISSUE: No authentication on delete — anyone can delete any user
router.delete('/:id', (req, res) => {
  const { id } = req.params;

  // ❌ SECURITY ISSUE: SQL injection
  const query = `DELETE FROM users WHERE id = ${id}`;

  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'User deleted', changes: this.changes });
  });
});

// ❌ SECURITY ISSUE: SQL injection in search via query parameter
router.get('/search/products', async (req, res) => {
  const { q } = req.query;
  try {
    const results = await searchProducts(q);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ❌ SECURITY ISSUE: XSS — reflecting user input directly into response HTML
router.get('/profile/view', (req, res) => {
  const { name } = req.query;
  // Never build HTML by concatenating user input
  res.send(`<html><body><h1>Welcome, ${name}!</h1></body></html>`);
});

module.exports = router;
