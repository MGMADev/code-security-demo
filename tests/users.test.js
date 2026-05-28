/**
 * Users & crypto tests
 * Provides code coverage for the GHAS demo workflow.
 */

const request = require('supertest');
const app = require('../src/app');
const { hashPasswordMD5, hashPasswordSHA1, generateToken, verifySecret } = require('../src/crypto');

// ── Users ──────────────────────────────────────────────────────────────────

describe('GET /users', () => {
  it('should return a list of users without authentication', async () => {
    const res = await request(app).get('/users');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
  });

  it('should return users with sensitive fields exposed', async () => {
    const res = await request(app).get('/users');
    // This test intentionally documents the vulnerability — passwords are returned
    expect(res.body[0]).toHaveProperty('password');
  });
});

describe('GET /users/profile/view', () => {
  it('should reflect name parameter into response HTML', async () => {
    const res = await request(app).get('/users/profile/view?name=Alice');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Alice');
  });

  it('should reflect XSS payload without sanitisation', async () => {
    const xss = '<script>alert(1)</script>';
    const res = await request(app)
      .get(`/users/profile/view?name=${encodeURIComponent(xss)}`);
    // Documents the XSS vulnerability — script tag is reflected unescaped
    expect(res.text).toContain('<script>alert(1)</script>');
  });
});

describe('GET /users/search/products', () => {
  it('should return products matching search term', async () => {
    const res = await request(app).get('/users/search/products?q=Widget');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// ── Crypto ─────────────────────────────────────────────────────────────────

describe('crypto utilities', () => {
  it('hashPasswordMD5 should return a 32-char hex string', () => {
    const hash = hashPasswordMD5('password');
    expect(hash).toHaveLength(32);
    expect(hash).toMatch(/^[a-f0-9]+$/);
  });

  it('hashPasswordSHA1 should return a 40-char hex string', () => {
    const hash = hashPasswordSHA1('password');
    expect(hash).toHaveLength(40);
  });

  it('generateToken should return a non-empty string', () => {
    const token = generateToken();
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  it('verifySecret should return true for matching strings', () => {
    expect(verifySecret('abc', 'abc')).toBe(true);
  });

  it('verifySecret should return false for non-matching strings', () => {
    expect(verifySecret('abc', 'xyz')).toBe(false);
  });
});
