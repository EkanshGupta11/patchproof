import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** The directory the endpoint is *supposed* to serve from. */
const PUBLIC_DIR = path.resolve(__dirname, '../../private/public');

/**
 * GET /files/:name
 *
 * VULN #2 — path traversal.
 *
 * The caller-supplied name is joined onto the public directory without being
 * normalised or confined, and `..` collapses during the join, so the read walks
 * out of PUBLIC_DIR into anything the process can open.
 *
 * Exploit (the traversal must stay inside a single path segment, so the slashes
 * are percent-encoded as %2F):
 *   /files/..%2Fsecret.txt              -> reads private/secret.txt
 *   /files/..%2F..%2F..%2Fetc%2Fpasswd  -> reads /etc/passwd (in the container)
 */
export function createFilesRouter() {
  const router = Router();

  router.get('/files/:name', (req, res) => {
    const name = req.params.name;

    // VULN #2: path.join happily normalises ".." away. A safe version would
    // resolve the path and assert it still starts with PUBLIC_DIR, e.g.
    //   const resolved = path.resolve(PUBLIC_DIR, name);
    //   if (!resolved.startsWith(PUBLIC_DIR + path.sep)) return res.sendStatus(403);
    const target = path.join(PUBLIC_DIR, name);

    try {
      const content = fs.readFileSync(target, 'utf8');
      res.json({ file: name, bytes: content.length, content });
    } catch {
      res.status(404).json({ error: `no such file: ${name}` });
    }
  });

  return router;
}
