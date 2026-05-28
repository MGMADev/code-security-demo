# GHAS Security Demo

A Node.js/Express application intentionally built with security vulnerabilities to demonstrate [GitHub Advanced Security (GHAS)](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security).

> ⚠️ **This code is deliberately insecure. Never use any of these patterns in production.**

---

## What this repo demonstrates

| GHAS Feature | What it finds in this repo |
|---|---|
| **CodeQL (SAST)** | SQL injection, path traversal, command injection, XSS, SSRF, ReDoS, insecure crypto |
| **Secret Scanning** | Hardcoded JWT secrets, AWS keys, Stripe API key, DB passwords |
| **Dependabot (SCA)** | Vulnerable versions of `lodash`, `express`, `axios`, `jsonwebtoken` with known CVEs |
| **Code Coverage** | Jest test suite with lcov report and Codecov integration |

---

## Vulnerabilities by file

### `src/auth.js`
- Hardcoded secrets: JWT secret, AWS keys, Stripe live key, DB password
- No rate limiting on `/login` (brute force)
- Plaintext password comparison
- Sensitive data (password, SSN) embedded in JWT payload
- Admin bypass via predictable `x-admin-bypass` header

### `src/db.js`
- SQL injection in `getUserByUsername` — raw string concatenation
- SQL injection in `searchProducts` — `LIKE '%${input}%'`
- SQL injection in `getUserById` — unvalidated numeric ID
- All queries return `password`, `ssn`, and `credit_card` fields

### `src/users.js`
- IDOR on `GET /users/:id` — no ownership check
- Mass assignment on `PUT /users/:id` — attacker can set `role: "admin"`
- Unauthenticated `GET /users` exposing all PII
- XSS via reflected query parameter in `/profile/view`

### `src/crypto.js`
- MD5 and SHA1 for password hashing (broken algorithms)
- DES-ECB encryption (broken cipher + mode)
- Hardcoded IV and encryption key
- `Math.random()` for security-sensitive token generation
- Non-constant-time string comparison (timing attack)

### `src/admin.js`
- Path traversal in `GET /admin/files` — no base directory check
- Command injection in `POST /admin/ping` via `exec()`
- SSRF in `POST /admin/fetch` — fetches any URL including cloud metadata
- No role check on admin routes
- ReDoS via catastrophic backtracking regex

### `package.json`
- `lodash@4.17.4` — CVE-2019-10744 (prototype pollution)
- `express@4.17.1` — multiple known CVEs
- `axios@0.21.1` — CVE-2021-3749 (ReDoS)
- `jsonwebtoken@8.5.1` — CVE-2022-23529 (remote code execution)

---

## Workflow

```
.github/
  workflows/
    ghas.yml        — CodeQL, dependency review, tests + coverage, summary
  dependabot.yml    — weekly npm + GitHub Actions updates
```

### Triggers
- **Push** to `main` / `develop`
- **Pull request** to `main` (also runs dependency review)
- **Schedule** — every Monday 08:00 UTC

### Jobs

```
CodeQL SAST ──────────────────────┐
Dependency Review (PRs only) ─────┤──▶ Security Summary
Secret Scanning (auto by GitHub) ─┤
Tests + Coverage ─────────────────┘
```

---

## Running locally

```bash
npm install
npm test          # runs Jest + lcov coverage
npm start         # starts server on :3000
```

---

## Enabling GHAS on your repo

1. Go to **Settings → Code security and analysis**
2. Enable: **Dependency graph**, **Dependabot alerts**, **Dependabot security updates**
3. Enable: **Code scanning** → set up with CodeQL
4. Enable: **Secret scanning** (+ push protection)
5. Push this repo — alerts will appear in the **Security** tab within minutes

---

## Expected CodeQL alert categories

After the workflow runs, you should see alerts in **Security → Code scanning alerts** including:

- `js/sql-injection`
- `js/path-injection`
- `js/command-line-injection`
- `js/server-side-request-forgery`
- `js/reflected-xss`
- `js/insecure-randomness`
- `js/polynomial-redos`
- `js/hardcoded-credentials`

Secret scanning will separately flag the hardcoded keys in `src/auth.js`.
