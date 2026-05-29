/**
 * Tests for crypto.js
 * Pure functions — no mocking needed.
 */

const {
  hashPasswordMD5,
  hashPasswordSHA1,
  encryptData,
  decryptData,
  generateToken,
  generatePasswordResetToken,
  verifySecret,
} = require('../src/crypto');

describe('hashPasswordMD5', () => {
  it('returns a 32-char hex string', () => {
    expect(hashPasswordMD5('password')).toHaveLength(32);
  });
  it('is deterministic for the same input', () => {
    expect(hashPasswordMD5('hello')).toBe(hashPasswordMD5('hello'));
  });
  it('produces different hashes for different inputs', () => {
    expect(hashPasswordMD5('abc')).not.toBe(hashPasswordMD5('xyz'));
  });
});

describe('hashPasswordSHA1', () => {
  it('returns a 40-char hex string', () => {
    expect(hashPasswordSHA1('password')).toHaveLength(40);
  });
  it('is deterministic', () => {
    expect(hashPasswordSHA1('test')).toBe(hashPasswordSHA1('test'));
  });
  it('differs from MD5 output', () => {
    expect(hashPasswordSHA1('password')).not.toBe(hashPasswordMD5('password'));
  });
});

describe('encryptData / decryptData', () => {
  // DES-ECB was deprecated and removed in OpenSSL 3 (Node 18+).
  // These tests document the vulnerability — the cipher is so weak
  // that modern runtimes refuse to run it at all.
  it('throws on Node 18+ because DES-ECB is removed from OpenSSL 3', () => {
    expect(() => encryptData('hello')).toThrow();
  });

  it('documents that DES-ECB should be replaced with AES-256-GCM', () => {
    // This is intentional — the code is a security demo showing insecure crypto.
    // The fix: use crypto.createCipheriv("aes-256-gcm", key, iv) with a random IV.
    expect(() => encryptData('test')).toThrow(/unsupported|unknown cipher|EVP/i);
  });
});

describe('generateToken', () => {
  it('returns a non-empty string', () => {
    const t = generateToken();
    expect(typeof t).toBe('string');
    expect(t.length).toBeGreaterThan(0);
  });
  it('returns different values on successive calls', () => {
    // Math.random — not guaranteed but statistically safe
    const tokens = new Set(Array.from({ length: 10 }, generateToken));
    expect(tokens.size).toBeGreaterThan(1);
  });
});

describe('generatePasswordResetToken', () => {
  it('returns an 8-char alphanumeric string', () => {
    const t = generatePasswordResetToken();
    expect(t).toHaveLength(8);
    expect(t).toMatch(/^[a-z0-9]+$/);
  });
  it('generates different tokens each time', () => {
    const tokens = new Set(Array.from({ length: 20 }, generatePasswordResetToken));
    expect(tokens.size).toBeGreaterThan(1);
  });
});

describe('verifySecret', () => {
  it('returns true when strings match', () => {
    expect(verifySecret('abc123', 'abc123')).toBe(true);
  });
  it('returns false when strings differ', () => {
    expect(verifySecret('abc', 'xyz')).toBe(false);
  });
  it('is case-sensitive', () => {
    expect(verifySecret('Secret', 'secret')).toBe(false);
  });
  it('returns false for empty vs non-empty', () => {
    expect(verifySecret('', 'something')).toBe(false);
  });
});

