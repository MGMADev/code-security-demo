/**
 * Database tests — partial coverage (demo purposes)
 */

jest.mock('sqlite3');

describe('db module', () => {
  let db;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    jest.mock('sqlite3');
    db = require('../src/db');
  });

  describe('getUserByUsername', () => {
    it('resolves with null when no user found', async () => {
      const result = await db.getUserByUsername('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('searchProducts', () => {
    it('resolves with an empty array when no products match', async () => {
      const result = await db.searchProducts('nothing');
      expect(Array.isArray(result)).toBe(true);
    });
  });
});
