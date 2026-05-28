/**
 * Crypto utilities
 * WARNING: Intentionally insecure cryptographic implementations for GHAS demo.
 */

const crypto = require('crypto');
const md5 = require('md5');

// ❌ SECURITY ISSUE: MD5 is cryptographically broken — don't use for passwords
function hashPasswordMD5(password) {
  return md5(password);
}

// ❌ SECURITY ISSUE: SHA1 is deprecated for security use
function hashPasswordSHA1(password) {
  return crypto.createHash('sha1').update(password).digest('hex');
}

// ❌ SECURITY ISSUE: Static/hardcoded IV — must be random per encryption
const STATIC_IV = Buffer.from('0000000000000000', 'hex'); // 8 bytes, always the same

// ❌ SECURITY ISSUE: Hardcoded encryption key
const ENCRYPTION_KEY = '0123456789abcdef'; // 16 bytes — hardcoded, not from env

function encryptData(data) {
  // ❌ SECURITY ISSUE: DES (not AES), and ECB mode leaks patterns
  const cipher = crypto.createCipheriv('des-ecb', Buffer.from('12345678'), null);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(encryptedData) {
  // ❌ SECURITY ISSUE: Same DES-ECB weakness
  const decipher = crypto.createDecipheriv('des-ecb', Buffer.from('12345678'), null);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ❌ SECURITY ISSUE: Math.random() is NOT cryptographically secure
function generateToken() {
  return Math.random().toString(36).substring(2);
}

// ❌ SECURITY ISSUE: Weak random for password reset tokens
function generatePasswordResetToken() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 8; i++) {
    // Math.random is predictable — should use crypto.randomBytes
    token += chars[Math.floor(Math.random() * chars.length)];
  }
  return token;
}

// ❌ SECURITY ISSUE: Timing attack vulnerability — string comparison not constant-time
function verifySecret(provided, expected) {
  return provided === expected; // Use crypto.timingSafeEqual instead
}

module.exports = {
  hashPasswordMD5,
  hashPasswordSHA1,
  encryptData,
  decryptData,
  generateToken,
  generatePasswordResetToken,
  verifySecret
};
