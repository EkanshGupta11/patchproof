import { Router } from 'express';

/**
 * GET /search?q=<term>
 *
 * VULN #1 — SQL injection.
 *
 * `q` is interpolated straight into the SQL string instead of being passed as a
 * bound parameter, so whatever the caller supplies is parsed as SQL.
 *
 * Exploit:
 *   q=%' UNION SELECT id, username, password, email FROM users--
 */
export function createSearchRouter(db) {
  const router = Router();

  router.get('/search', (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q : '';

    try {
      // VULN #1: string interpolation into SQL. Should be a bound parameter:
      //   db.prepare('SELECT ... WHERE name LIKE ?').all(`%${q}%`)
      const statement = db.prepare(
        `SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%'`,
      );
      const results = statement.all();

      res.json({ query: q, count: results.length, results });
    } catch (error) {
      // Leaking the SQL error is itself sloppy, but the injection above already
      // lets an attacker read anything in the database.
      res.status(500).json({ error: error.message });
    }
  });

  return router;
}

// patched by check-tools
