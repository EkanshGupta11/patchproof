# syntax=docker/dockerfile:1
#
# PatchProof sandbox: a minimal, deliberately network-less attacker's toolbox.
#
# What is in here, and nothing else:
#   * Node 22 (runtime for the target app and for any Node-based exploit)
#   * curl (every exploit in this project is an HTTP request)
#
# The target application is NOT baked into this image. It is mounted in as a
# volume at run time, so the sandbox and the target can be swapped or patched
# independently and without rebuilding.
#
# Isolation is enforced at RUN time, not here -- an image cannot prevent a
# network connection on its own:
#   docker run --network none ...
# That leaves the container with only a loopback interface, so it can reach a
# target running alongside it but has no route to the internet.
# See sandbox/README.md.

FROM node:22-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Where the target app is expected to be mounted.
WORKDIR /workspace/target

# Stay alive so the container can be driven with `docker exec`, which is how the
# orchestrator runs exploits. There is no long-running service here on purpose.
CMD ["sleep", "infinity"]