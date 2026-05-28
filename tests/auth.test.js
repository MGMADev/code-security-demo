/**
 * Auth route tests
 * These tests provide code coverage for the GHAS demo workflow.
 */

const request = require('supertest');
const app = require('../src/app');

describe('POST /auth/login', () => {
  it('should return 400 when credentials are missing', async () => {
    const res = await request(app).post('/auth/login').send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('should return 401 for invalid username', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'nonexistent', password: 'wrong' });
    expect(res.status).toBe(401);
  });

  it('should return 200 and a token for valid credentials', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
  });

  it('should return a token for alice with correct password', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ username: 'alice', password: 'password' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
  });
});

describe('POST /auth/admin-login', () => {
  it('should allow admin bypass with the correct header', async () => {
    const res = await request(app)
      .post('/auth/admin-login')
      .set('x-admin-bypass', 'letmein')
      .send({});
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
  });

  it('should reject when neither header nor password match', async () => {
    const res = await request(app)
      .post('/auth/admin-login')
      .send({ password: 'wrong' });
    expect(res.status).toBe(403);
  });
});
