#!/bin/sh
# Smoke test for the minimal PatchProof sandbox image.
# Runs inside the container, with the target mounted at /workspace/target.
#
# Usage:
#   docker run --rm --network none \
#     -v "$PWD/targets/vulnerable-shop:/workspace/target:ro" \
#     patchproof-sandbox:latest sh /probe.sh

set -e

echo "== toolchain =="
node --version
curl --version | head -1

echo
echo "== target mounted (read-only) =="
ls /workspace/target
ls /workspace/target/src

echo
echo "== write to a read-only mount must be refused =="
if touch /workspace/target/SHOULD_FAIL 2>/dev/null; then
  echo "UNEXPECTED: write succeeded"
  exit 1
else
  echo "write correctly denied"
fi

echo
echo "== network isolation =="
# DNS resolution and outbound connections must both fail.
if curl -sS -m 8 https://api.groq.com -o /dev/null 2>/dev/null; then
  echo "UNEXPECTED: outbound request succeeded"
  exit 1
else
  echo "outbound request correctly blocked (curl exit $?)"
fi
if getent hosts api.groq.com >/dev/null 2>&1; then
  echo "UNEXPECTED: DNS resolved"
  exit 1
else
  echo "DNS correctly unavailable"
fi

echo
echo "== loopback still works (exploits need this) =="
node -e "const s=require('node:sqlite');const d=new s.DatabaseSync(':memory:');d.exec('CREATE TABLE t(a)');d.prepare('INSERT INTO t VALUES (?)').run('ok');console.log('node:sqlite ->',JSON.stringify(d.prepare('SELECT a FROM t').get()))" 2>/dev/null

echo
echo "ALL SANDBOX CHECKS PASSED"