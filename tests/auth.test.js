/**
 * Auth route tests
 */

jest.mock('sqlite3');
jest.mock('../src/db', () => ({
  getUserByUsername: jest.fn(),
}));

const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db');

beforeEach(() => jest.clearAllMocks());

describe('POST /auth/login', () => {
  it('returns 400 when body is empty', async () => {
    const res = await request(app).post('/auth/login').send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 when password is missing', async () => {
    const res = await request(app).post('/auth/login').send({ username: 'admin' });
    expect(res.status).toBe(400);
  });

  it('returns 400 when username is missing', async () => {
    const res = await request(app).post('/auth/login').send({ password: 'pass' });
    expect(res.status).toBe(400);
  });

  it('returns 401 when user does not exist', async () => {
    db.getUserByUsername.mockResolvedValue(null);
    const res = await request(app).post('/auth/login').send({ username: 'ghost', password: 'x' });
    expect(res.status).toBe(401);
  });

  it('returns 401 when password is wrong', async () => {
    db.getUserByUsername.mockResolvedValue({ id: 1, username: 'admin', password: 'admin123', role: 'user' });
    const res = await request(app).post('/auth/login').send({ username: 'admin', password: 'wrong' });
    expect(res.status).toBe(401);
  });

  it('returns 200 and a token for valid credentials', async () => {
    db.getUserByUsername.mockResolvedValue({ id: 1, username: 'admin', password: 'admin123', role: 'admin' });
    const res = await request(app).post('/auth/login').send({ username: 'admin', password: 'admin123' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(res.body).toHaveProperty('userId', 1);
  });

  it('returns 500 when db throws', async () => {
    db.getUserByUsername.mockRejectedValue(new Error('DB down'));
    const res = await request(app).post('/auth/login').send({ username: 'admin', password: 'admin123' });
    expect(res.status).toBe(500);
  });
});

describe('POST /auth/admin-login', () => {
  it('grants access with the bypass header', async () => {
    const res = await request(app)
      .post('/auth/admin-login')
      .set('x-admin-bypass', 'letmein')
      .send({});
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
  });

  it('grants access with the hardcoded admin password', async () => {
    const res = await request(app)
      .post('/auth/admin-login')
      .send({ password: 'admin123' });
    expect(res.status).toBe(200);
  });

  it('returns 403 for wrong credentials', async () => {
    const res = await request(app)
      .post('/auth/admin-login')
      .send({ password: 'wrong' });
    expect(res.status).toBe(403);
  });
});
