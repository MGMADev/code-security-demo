/**
 * Admin route tests — partial coverage (demo purposes)
 */

jest.mock('sqlite3');
jest.mock('../src/db', () => ({
  getAllUsers: jest.fn().mockResolvedValue([
    { id: 1, username: 'admin', password: 'admin123', role: 'admin', ssn: '123-45-6789' },
  ]),
}));
jest.mock('fs');
jest.mock('child_process');
jest.mock('axios');

const request = require('supertest');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const app = require('../src/app');

const TOKEN_SECRET = 'super_secret_key_1234';
const adminToken = jwt.sign({ id: 1, username: 'admin', role: 'admin' }, TOKEN_SECRET);

beforeEach(() => jest.clearAllMocks());

describe('GET /admin/files', () => {
  it('returns 401 without a token', async () => {
    const res = await request(app).get('/admin/files?name=report.txt');
    expect(res.status).toBe(401);
  });
});

describe('POST /admin/ping', () => {
  it('returns 401 without a token', async () => {
    const res = await request(app).post('/admin/ping').send({ host: 'google.com' });
    expect(res.status).toBe(401);
  });
});
