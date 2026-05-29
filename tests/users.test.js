/**
 * Users route tests
 */

jest.mock('sqlite3');
jest.mock('../src/db', () => ({
  getAllUsers: jest.fn(),
  getUserById: jest.fn(),
  searchProducts: jest.fn(),
  db: {
    run: jest.fn((sql, cb) => cb && cb.call({ changes: 1 }, null)),
  },
}));

const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const db = require('../src/db');

const TEST_SECRET = 'super_secret_key_1234';
const userToken = jwt.sign({ id: 2, username: 'alice', role: 'user' }, TEST_SECRET);
const adminToken = jwt.sign({ id: 1, username: 'admin', role: 'admin' }, TEST_SECRET);

beforeEach(() => jest.clearAllMocks());

describe('GET /users', () => {
  it('returns all users without authentication', async () => {
    db.getAllUsers.mockResolvedValue([
      { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
      { id: 2, username: 'alice', password: 'password', role: 'user' },
    ]);
    const res = await request(app).get('/users');
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
  });

  it('returns 500 on db error', async () => {
    db.getAllUsers.mockRejectedValue(new Error('DB error'));
    const res = await request(app).get('/users');
    expect(res.status).toBe(500);
  });

  it('exposes the password field (documents vulnerability)', async () => {
    db.getAllUsers.mockResolvedValue([{ id: 1, username: 'admin', password: 'admin123' }]);
    const res = await request(app).get('/users');
    expect(res.body[0]).toHaveProperty('password');
  });
});

describe('GET /users/:id', () => {
  it('returns a user when found', async () => {
    db.getUserById.mockResolvedValue({ id: 2, username: 'alice', role: 'user' });
    const res = await request(app).get('/users/2').set('authorization', userToken);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('username', 'alice');
  });

  it('returns 404 when user not found', async () => {
    db.getUserById.mockResolvedValue(null);
    const res = await request(app).get('/users/999').set('authorization', userToken);
    expect(res.status).toBe(404);
  });

  it('returns 401 without a token', async () => {
    const res = await request(app).get('/users/1');
    expect(res.status).toBe(401);
  });

  it('returns 500 on db error', async () => {
    db.getUserById.mockRejectedValue(new Error('DB error'));
    const res = await request(app).get('/users/1').set('authorization', userToken);
    expect(res.status).toBe(500);
  });
});

describe('GET /users/search/products', () => {
  it('returns matching products', async () => {
    db.searchProducts.mockResolvedValue([{ id: 1, name: 'Widget A', price: 9.99 }]);
    const res = await request(app).get('/users/search/products?q=Widget');
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });

  it('returns empty array when nothing matches', async () => {
    db.searchProducts.mockResolvedValue([]);
    const res = await request(app).get('/users/search/products?q=nothing');
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(0);
  });

  it('returns 500 on db error', async () => {
    db.searchProducts.mockRejectedValue(new Error('Search error'));
    const res = await request(app).get('/users/search/products?q=Widget');
    expect(res.status).toBe(500);
  });
});

describe('GET /users/profile/view', () => {
  it('reflects the name parameter in the HTML response', async () => {
    const res = await request(app).get('/users/profile/view?name=Alice');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Alice');
  });

  it('reflects an XSS payload unescaped (documents vulnerability)', async () => {
    const xss = encodeURIComponent('<script>alert(1)</script>');
    const res = await request(app).get(`/users/profile/view?name=${xss}`);
    expect(res.text).toContain('<script>alert(1)</script>');
  });
});


