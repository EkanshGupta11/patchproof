# Sandbox

The isolated environment where PatchProof **actually runs exploits**.

The promise "we didn't just read the code, we exploited it" is only meaningful if
the attack happens somewhere disposable and contained. This folder is that place.

## The image

`sandbox/Dockerfile` is deliberately tiny:

```
node:22-slim  +  curl
```

That's it. Node runs the target app; `curl` runs the exploits (every exploit in
this project is an HTTP request). Nothing else is installed, because a sandbox
should not carry attack surface it doesn't need.

The target application is **not** baked into the image. It is mounted in at run
time as a volume, so the image stays generic and can be pointed at any target
under test — and so patching the target never requires a rebuild.

## No network, enforced at run time

The image itself cannot prevent a network connection. Isolation comes from how
the container is started:

```bash
docker run --network none ...
```

That leaves the container with a loopback interface only. Verified behaviour:

| Check | Result |
| --- | --- |
| `curl https://api.groq.com` | fails, exit 6 — no route out |
| `getent hosts api.groq.com` | fails — no DNS at all |
| `curl http://127.0.0.1:3000/...` | works — loopback is intact |

That last row is the important one. Exploits are HTTP requests to the target, so
the sandbox must be able to reach a target running alongside it. Loopback is the
only thing it gets.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | the image definition |
| `docker-compose.yml` | wires the volume, `network_mode: none`, and resource limits |
| `probe.sh` | self-test: toolchain, volume mount, isolation, loopback |
| `exploit-check.sh` | starts the target inside the sandbox and runs all three exploits |

## Usage

```bash
npm run build     # docker build
npm test          # run the self-test in a throwaway container
npm run up        # stay alive for docker exec
npm run shell     # shell inside the sandbox
npm run down      # tear down
```

Manual invocation, if you'd rather not use compose:

```bash
docker build -t patchproof-sandbox:latest -f sandbox/Dockerfile sandbox

docker run --rm --network none \
  -v "$PWD/sandbox:/scripts:ro" \
  -v "$PWD/targets/vulnerable-shop:/workspace/target:ro" \
  patchproof-sandbox:latest sh /scripts/probe.sh
```

## Notes and gotchas

- **`node:sqlite` on Node 22 prints an `ExperimentalWarning`** on stderr. It
  works; the warning is noise. Set `NODE_NO_WARNINGS=1` to silence it.
- **`node_modules` must come from the host mount.** The sandbox has no network,
  so `npm install` cannot run inside it. The target's dependencies are installed
  on the host (they are pure-JS, so they work on Linux) and arrive via the volume.
- **The target mount is `:ro`.** Writes are refused, verified by `probe.sh`. If a
  later step needs to write (for example applying a patch from inside the
  container), mount a second, writable copy rather than loosening this one.
- **Shell scripts need LF line endings.** Git's default `core.autocrlf` on Windows
  turns them into CRLF, which `/bin/sh` refuses to run (`Illegal option`). This
  project's scripts are stored with LF endings.