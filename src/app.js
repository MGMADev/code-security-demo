/**
 * GHAS Security Demo - Main Application
 * WARNING: This file contains intentional security vulnerabilities for demo purposes.
 */

const express = require('express');
const app = express();

// ❌ SECURITY ISSUE: No helmet, no rate limiting, no CORS policy
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authRouter = require('./auth');
const usersRouter = require('./users');
const adminRouter = require('./admin');

app.use('/auth', authRouter);
app.use('/users', usersRouter);
app.use('/admin', adminRouter);

// ❌ SECURITY ISSUE: Verbose error messages expose stack traces to clients
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack,        // Never expose stack traces in production
    details: err.toString()
  });
});

// Only start the server if this file is run directly (not imported by tests)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
