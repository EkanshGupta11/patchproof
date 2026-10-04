# PatchProof

**Prove it, don't guess it.**

Most "AI security scanners" hand you a list of suspicions. PatchProof refuses to report anything it
has not first *executed*. For every candidate vulnerability it builds a real exploit, runs it against
the target inside an isolated Docker sandbox, and only treats the finding as real if the target
actually misbehaves. Then it patches the code and **re-verifies the fix by replaying the exact same
exploit** against the patched build.

If the replayed exploit no longer succeeds, the patch is proven. If it still succeeds, the fix is
rejected. Nothing reaches the report on the model's opinion alone.

---

## Table of contents

1. [Requirements](#requirements)
2. [Setup](#setup-linux--macos)
3. [Environment variables](#environment-variables)
4. [Running the project](#running-the-project)
5. [Verification commands](#verification-commands)
6. [How it works](#how-it-works)
7. [Repository layout](#repository-layout)
8. [Dependencies](#dependencies)
9. [API reference](#api-reference)
10. [Troubleshooting](#troubleshooting)
11. [Security warning](#security-warning)

---

## Requirements

| Requirement | Version | Notes |
| --- | --- | --- |
| **Node.js** | **22 or later** | The Cline SDK requires it. Developed and tested against 24.x. |
| **npm** | 10 or later | Ships with Node 22. |
| **Docker** | 24 or later | The sandbox runs in Docker. Must be **running**, not just installed. |
| **Groq API key** | - | Primary LLM provider. Free tier works; see [Cost control](#cost-control). |
| **GitHub token** | optional | Only needed to open pull requests on approval. |

Check them:

```bash
node --version    # must print v22.x or higher
npm --version
docker --version
docker info >/dev/null && echo "Docker daemon is running"
```

### Install prerequisites

**Ubuntu / Debian**

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**macOS (Homebrew)**

```bash
brew install node@22
# If node --version is still below 22, run:
brew link --overwrite --force node@22
```

Or install Node 22 or later from [nodejs.org](https://nodejs.org/en/download).

---

## Setup (Linux & macOS)

Every step below is identical on Linux and macOS. There are no OS-specific paths.

```bash
git clone <your-repo-url> patchproof
cd patchproof
```

### 1. Install all sub-projects

Installs the target app, the orchestrator, the sandbox tooling and the dashboard:

```bash
npm run install:all
```

> **The target's `node_modules` must be installed on the host.** The sandbox container has
> `--network none`, so `npm install` cannot run inside it. `targets/vulnerable-shop/node_modules`
> is mounted in from the host instead. The dependencies are pure JavaScript, so they work on Linux.

### 2. Build the sandbox image

**Required.** The orchestrator creates a throwaway container per command from this image:

```bash
npm run sandbox:build
docker images | grep patchproof-sandbox    # confirm it exists
```

> You do **not** need `npm run sandbox:up`. That starts a long-lived compose container used only by
> the optional sandbox smoke test. A normal pipeline run spawns its own `docker run --rm` container
> each time.

### 3. Configure your API keys

```bash
cp orchestrator/.env.example orchestrator/.env
```

Edit `orchestrator/.env` and paste your Groq key:

```dotenv
GROQ_API_KEY=gsk_your_real_key_here
```

Optionally add a backup provider (recommended, because Groq's free tier is easy to exhaust):

```dotenv
BACKUP_LLM_PROVIDER=gemini
---

## Environment variables

All variables live in `orchestrator/.env`. The defaults below are the ones compiled into
`orchestrator/src/config.ts`, so they work even if the variable is absent.

### LLM providers

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `GROQ_API_KEY` | *(none)* | **Yes** | Primary provider key from [console.groq.com](https://console.groq.com/keys). |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | No | Use `qwen/qwen3.8-27b`. Reasoning models fail on tool loops through this SDK. |
| `GROQ_API_BASE_URL` | `https://api.groq.com/openai/v1` | No | Groq's OpenAI-compatible endpoint. |
| `BACKUP_LLM_PROVIDER` | `gemini` | No | One of `gemini` or `anthropic`. |
| `GEMINI_API_KEY` | *(none)* | No | Backup provider key. |
| `GEMINI_MODEL` | `gemini-3.8-flash` | No | |
| `ANTHROPIC_API_KEY` | *(none)* | No | Only when `BACKUP_LLM_PROVIDER=anthropic`. |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | No | |
| `ANTHROPIC_API_BASE_URL` | `https://api.anthropic.com` | No | |

### LLM fallback behaviour

| Variable | Default | Description |
| --- | --- | --- |
| `LLM_MAX_RETRIES` | `0` | Extra attempts per provider before falling back. **Keep at 0.** A retry against a rate-limited provider still bills tokens, so retries burn the daily budget without doing the work. |
| `LLM_FALLBACK_ON_STATUS_CODES` | `429,503` | HTTP statuses that trigger a fallback. |
| `LLM_FALLBACK_ON_CONTENT_FILTER` | `true` | Fall back when a provider refuses for content reasons. |

### Agent runtime

| Variable | Default | Description |
| --- | --- | --- |
| `AGENT_MAX_ITERATIONS` | `12` | Loop budget per agent run. **Do not go below 12.** The exploit flow (recon, write script, run) does not fit in fewer, and findings fail with `maxIterations`. |
| `AGENT_PROVIDER_TIMEOUT_MS` | `120000` | Per-provider call timeout. |
| `AGENT_CONCURRENCY` | `1` | Findings processed at once. `1` is sequential. Parallel agents multiply the request rate and cause rate limiting. |
| `AGENT_THROTTLE_MS` | `2000` | Minimum pause between agent requests. |

### Server

| Variable | Default | Description |
| --- | --- | --- |
| `NODE_ENV` | `development` | |
| `PORT` | `4000` | Orchestrator HTTP port. |
| `LOG_LEVEL` | `info` | Use `debug` to trace agent steps. |
| `PATCHPROOF_WORKSPACE` | `.patchproof` | Where reports and diffs are written. |

### Target application

| Variable | Default | Description |
| --- | --- | --- |
| `TARGET_APP_PATH` | `../targets/vulnerable-shop` | **Relative to `orchestrator/`.** |
| `TARGET_BASE_URL` | `http://localhost:3000` | URL as seen *inside* the sandbox container. |
| `TARGET_SOURCE_GLOB` | `src/**/*.js` | What gets scanned. |
| `TARGET_PORT` | `3000` | Port the app listens on in the container. |
| `TARGET_START_COMMAND` | `node src/server.js` | How the sandbox boots the target. |

### Docker sandbox

| Variable | Default | Description |
| --- | --- | --- |
| `SANDBOX_IMAGE` | `patchproof-sandbox:latest` | **Must exist.** Build it with `npm run sandbox:build`. |
| `SANDBOX_CONTAINER_NAME` | `patchproof-sandbox` | |
| `SANDBOX_NETWORK` | `none` | Loopback only. Do not change without reading the isolation notes. |
| `SANDBOX_MOUNT_PATH` | `/workspace/target` | Where the target is mounted in the container. |
| `SANDBOX_MEMORY` | `512m` | |
| `SANDBOX_CPUS` | `1.0` | |
| `SANDBOX_PIDS_LIMIT` | `256` | Fork-bomb guard. |
| `SANDBOX_TIMEOUT_MS` | `60000` | Per-command wall-clock limit. |
| `SANDBOX_READY_TIMEOUT_SEC` | `60` | How long to wait for the target to boot. |

### GitHub (optional)

| Variable | Default | Description |
| --- | --- | --- |
| `GITHUB_TOKEN` | *(none)* | Token with `repo` scope. Without it, approval applies the fix locally instead of opening a PR. |
| `GITHUB_DEFAULT_REPO` | *(none)* | `owner/name` default. **You usually do not need to set this** — the dashboard has a field that overrides it at runtime. |

### Dashboard

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `/api` | Set in `dashboard/.env`. `/api` is proxied to `localhost:4000` by Vite, which avoids CORS in development. |
GEMINI_API_KEY=your_gemini_key
```

Everything else has a working default. See [Environment variables](#environment-variables).

### 4. Verify the install

```bash
npm run test:target                        # 13 tests, all should pass
npm --prefix orchestrator run check:scan   # must report 3 findings
```

`check:scan` runs the real scanner and must find all three: command injection, path traversal and
SQL injection. If it reports fewer, the target source is probably not in its vulnerable state (see
[Troubleshooting](#troubleshooting)).
---

## Running the project

You need **two terminals**. The orchestrator must be started **from the `orchestrator/` directory**.

### Terminal 1 — orchestrator (agents + API, port 4000)

```bash
cd orchestrator
npm run dev          # watch mode, TypeScript run directly via tsx
```

Or run the compiled build:

```bash
cd orchestrator
npm run build
npm start
```

> **Why the `cd` matters.** `dotenv` resolves `.env` against `process.cwd()`. Starting the server from
> the repository root silently loads nothing — there is no error, every key is simply `undefined`,
> and the UI then reports `no GITHUB_TOKEN` while the boot log shows `NO API KEY SET`. The tell is
> the model name: if it prints `llama-3.3-70b-versatile` instead of `qwen/qwen3.8-27b`, your `.env`
> was not loaded.

### Terminal 2 — dashboard (UI, port 5173)

```bash
cd dashboard
npm run dev
```

Open **<http://localhost:5173>**.

### No third terminal needed

The sandbox is created and destroyed automatically by the orchestrator. There is no long-running
container to start.

### Confirm it is healthy

```bash
curl http://localhost:4000/api/health
# {"ok":true,"service":"patchproof-orchestrator","target":"vulnerable-shop"}

curl http://localhost:4000/api/config
```

If you set `GITHUB_TOKEN`, `github.tokenConfigured` should be `true`.

### Run it from the UI

1. Set **findings** to `3`. It defaults to `1`, which processes only the first finding found.
2. Optionally paste a GitHub repo into the **GitHub repo for PRs** field.
3. Click **Start run**.

### Run it from the command line

```bash
# every finding
curl -X POST http://localhost:4000/api/runs \
  -H 'Content-Type: application/json' -d '{}'

# only SQL injection, first one only
curl -X POST http://localhost:4000/api/runs \
  -H 'Content-Type: application/json' \
  -d '{"maxFindings":1,"onlyClasses":["sql-injection"]}'

# watch progress live (Server-Sent Events)
RUN_ID=<the id returned above>
curl -N http://localhost:4000/api/runs/$RUN_ID/stream

# full result afterwards
curl http://localhost:4000/api/runs/$RUN_ID
```

### Cost control

A full run costs real LLM tokens. Groq's free tier allows roughly 8,000 input tokens per minute and
200,000 tokens per day. To stay inside a free tier:

- Set **findings** to `1` or `2`, not `20`.
- Leave `LLM_MAX_RETRIES=0` (the default) — retries bill tokens even when they fail.
- Leave `AGENT_CONCURRENCY=1` (the default) — parallel agents multiply the request rate.
- Expect roughly 1 to 2 minutes per finding.

---

## Verification commands

Each of these is a self-contained check that prints `ok` lines on success.

```bash
# deterministic, no LLM and no Docker needed
npm --prefix orchestrator run check:scan     # must report 3 findings
npm run test:target                         # 13 tests

# builds must be clean
npm run build:orchestrator
npm run build:dashboard

# deeper suites
npm --prefix orchestrator run check:deps         # dependency wiring
npm --prefix orchestrator run check:resilience   # provider fallback, concurrency
npm --prefix orchestrator run check:proof        # deterministic before/after replay
npm --prefix orchestrator run check:pr           # pull request generation, stubbed API
npm --prefix orchestrator run check:no-llm       # the verifier never calls a model
npm --prefix dashboard run test                  # SSE reducer
```

Sandbox-specific, requires the image to be built:

```bash
npm --prefix orchestrator run check:ephemeral    # boots the target inside a container
npm --prefix orchestrator run smoke:sandbox      # compose-based smoke test
```
---

## How it works

```
  target source              agents (Cline SDK)                 sandbox (Docker)
  -------------->  scan --> exploit --> patch --> verify  <------- isolated replay
                             |                     |
                             `-- exploit must ------'
                                 actually fire
```

### 1. Scan — deterministic

ESLint plus `eslint-plugin-security` over the target source, plus one local rule
(`patchproof/detect-sql-string-concat`) that catches string-concatenated SQL, which no upstream
security ruleset covers. Runs in well under a second and needs no LLM, so a provider outage can
never reduce your coverage.

### 2. Exploit — the confirmation gate

An agent writes a real exploit for each candidate. **Its claim is then discarded**: the orchestrator
replays the exploit itself, independently, inside a throwaway container, and a detector judges the
raw output.

The detector only accepts evidence a *patched* target cannot produce. An exploit that "confirms" a
bug by returning HTTP 200, or the string `results`, proves nothing and is explicitly rejected.

### 3. Patch

An agent produces a minimal fix for the confirmed vulnerability and writes a test script beside it.

### 4. Verify — deterministic, no model involved

The orchestrator replays the **same exploit twice**: once against the original code, once against the
patched code, then runs the target's functional test suite.

| Outcome | Verdict |
| --- | --- |
| Exploit fires before, fails after, tests pass | `verified` |
| Exploit still fires after the patch | `regression` |
| Tests fail after the patch | `functional-break` |
| Exploit never fired even *before* the patch | `inconclusive` |

This phase never calls a model, which is what makes the verdict reproducible and trustworthy.

### Why the ordering matters

Each stage narrows the one before it. Scan proposes, exploit disposes, patch proposes a fix, verify
disposes of the fix. A finding can only reach a report by surviving all four, and only a fix that
defeats a replayed exploit is ever approved for shipping.

---

## Repository layout

| Path | Purpose |
| --- | --- |
| `orchestrator/` | Node + TypeScript backend. Runs the agents, owns the sandbox, serves the API. |
| `dashboard/` | React + Vite frontend. Watches the pipeline over Server-Sent Events. |
| `sandbox/` | Docker image definition for the isolated sandbox. |
| `targets/vulnerable-shop/` | Intentionally vulnerable Express app (the thing under attack). |

Key files:

| File | Purpose |
| --- | --- |
| `orchestrator/src/config.ts` | Every environment variable and its default, in one place. |
| `orchestrator/src/pipeline.ts` | Orchestrates the four phases and emits events. |
| `orchestrator/src/agents/exploitAgent.ts` | The confirmation gate. |
| `orchestrator/src/verify/proveFix.ts` | Deterministic before/after replay. Never calls a model. |
| `orchestrator/src/scan/detectors.ts` | Decides whether output actually proves a vulnerability. |
| `orchestrator/src/sandbox/ephemeral.ts` | One throwaway container per command. |
| `orchestrator/src/scan/sqlInjectionRule.ts` | Local ESLint rule for concatenated SQL. |

---

## Dependencies

### Runtime — `orchestrator/`

| Package | Version | Used for |
| --- | --- | --- |
| `@cline/sdk` | `^0.0.90` | Agent runtime and model providers |
| `@octokit/rest` | `^22.0.1` | Opening pull requests |
| `express` | `^4.21.2` | HTTP API |
| `cors` | `^2.8.5` | CORS for the dashboard |
| `dotenv` | `^16.4.5` | Loading `.env` |
| `zod` | `^4.3.6` | Tool input schemas |

### Dev — `orchestrator/`

`typescript` · `tsx` · `@types/node` · `@types/express` · `@types/cors` · `eslint` · `@eslint/js` ·
`eslint-plugin-security` · `eslint-plugin-no-unsanitized`

### Runtime — `targets/vulnerable-shop/`

| Package | Version |
| --- | --- |
| `express` | `^4.21.2` |

Uses Node's built-in `node:sqlite`, so there is no database dependency.

### Runtime — `dashboard/`

`react` `^18.3.1` · `react-dom` `^18.3.1` · `vite` `^5.4.11` · `@vitejs/plugin-react` `^4.3.4` ·
`typescript` `^5.7.2` · `@types/react` · `@types/react-dom`

### Docker image

`node:22-slim` plus `curl`. Nothing else.
---

## API reference

Base URL `http://localhost:4000`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness check. |
| `GET` | `/api/config` | Non-secret configuration, including `github.tokenConfigured`. |
| `PUT` | `/api/config/repo` | Set the PR target repo. Body `{ "repo": "owner/name" }`, or `{ "repo": null }` to clear. Accepts a pasted GitHub URL. |
| `POST` | `/api/runs` | Start a run. Body `{ "maxFindings"?: number, "onlyClasses"?: string[] }`. Returns `202` with `{ runId }`. |
| `GET` | `/api/runs` | List runs. |
| `GET` | `/api/runs/:id` | Full run state: candidates, findings, patches, verifications. |
| `GET` | `/api/runs/:id/stream` | Server-Sent Events. Replays history, streams live, then closes. |
| `POST` | `/api/runs/:id/approvals` | Approve a verified fix. Body `{ "findingId" }`. Refuses anything not `verified`. |
| `GET` | `/api/approvals` | List approvals. |

---

## Troubleshooting

**Boot log says `llama-3.3-70b-versatile` instead of `qwen/qwen3.8-27b`**
Your `.env` was not loaded, because the server was started from the wrong directory. Run `cd
orchestrator` first. This is the most common setup mistake and it fails silently.

**UI shows `no GITHUB_TOKEN` but the key is in `.env`**
Same cause, or the browser tab was open across a server restart — the dashboard fetches `/api/config`
once on mount. Hard-refresh the page.

**`scan found 2 candidate(s)` instead of 3**
The target source has been patched. `proveFix` restores the originals in a `finally` block, but if
the orchestrator is killed mid-run the restore never happens. Restore it:

```bash
git checkout -- targets/vulnerable-shop/src   # if committed
npm run test:target                          # expect 13 passing
npm --prefix orchestrator run check:scan     # expect 3 findings
```

A count of 2 is a strong signal that a previous run was interrupted.

**`Agent runtime exceeded maxIterations`**
`AGENT_MAX_ITERATIONS` is too low. Set it to `12` in `orchestrator/.env` and restart.

**`Rate limit reached ... tokens per day (TPD)`**
You have exhausted your provider quota. Raising `LLM_MAX_RETRIES` makes it worse, because retries
still bill tokens. Wait for the daily reset, add a working `GEMINI_API_KEY`, or lower the **findings**
count.

**`The response was blocked by a content filter`**
Gemini's safety filter rejected the exploit prompt. Use a different backup
(`BACKUP_LLM_PROVIDER=anthropic`) or give the primary provider a larger quota.

**`docker: image not found` / `Error response from daemon`**
The sandbox image is missing. Run `npm run sandbox:build`.

**`Cannot find module ... node_modules`**
The target's dependencies were never installed. Run `npm run install:all`.

**Port 4000 or 5173 already in use**
Set `PORT=4001` in `orchestrator/.env` and update the proxy target in `dashboard/vite.config.ts`.

**Dashboard shows no events**
The orchestrator is not running, or no run has been started. Check <http://localhost:4000/api/health>.

**Exploit rejected as `inconclusive`**
The verifier reports this when the exploit did not fire even against the *original* code, so there
is no baseline to compare against. Usually the target is already patched — see the `scan found 2`
entry above.

---

## Security warning

`targets/vulnerable-shop` contains **three intentional, unfixed vulnerabilities**:

| Class | Endpoint | What it allows |
| --- | --- | --- |
| SQL injection | `GET /search?q=` | Read any table, including stored credentials |
| Path traversal | `GET /files/:name` | Read any file the process can open |
| Command injection | `POST /convert` | Arbitrary shell command execution |

- Run it **only** inside the sandbox container.
- **Never** deploy it to a public network or expose it on an untrusted interface.
- The sandbox runs with `--network none` (loopback only), bounded CPU, memory and PID limits, and
  mounts the target read-only by default.
- It exists purely as a crash-test dummy for PatchProof.

Defeating these three is exactly what the pipeline is built to demonstrate.

---

## License

Provided as-is for evaluation purposes.