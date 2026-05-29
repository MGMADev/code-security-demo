/**
 * Manual mock for sqlite3 — replaces the native module in all tests.
 * Each test can override these implementations via jest.fn() as needed.
 */

const mockDb = {
  serialize: jest.fn((cb) => cb && cb()),
  run: jest.fn((sql, cb) => cb && cb(null)),
  get: jest.fn((sql, cb) => cb && cb(null, null)),
  all: jest.fn((sql, cb) => cb && cb(null, [])),
  close: jest.fn(),
};

const sqlite3 = {
  verbose: jest.fn(() => sqlite3),
  Database: jest.fn(() => mockDb),
};

module.exports = sqlite3;
module.exports.mockDb = mockDb;
