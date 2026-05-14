---
title: "Containers — Dockerfile rules"
description: "Triaging VNX-DOCKER-* findings: per-rule fixes for the eight built-in Dockerfile rules."
weight: 40
---

Container scanning in Vulnetix evaluates the eight `VNX-DOCKER-*` Rego rules against **build-time files** — `Dockerfile`, `Containerfile`, and the `*.dockerfile` / `*.containerfile` variants. The flag `--enable-containers` turns this on (it's gated, not on-by-default like SCA / SAST / secrets).

Image-layer scanning (extracting packages from a built OCI image and emitting them as SBOM components) is **not part of the current container evaluator**. If you need vulnerability findings against a base-image's `apk` / `deb` / `rpm` packages, run a separate dedicated image scanner — Grype, Trivy, or `vulnetix scan` against an exported root filesystem after `docker export | tar -x`. The findings then triage through the standard [SCA path](../sca/).

## What container scanning finds

Findings land in `.vulnetix/sast.sarif` with `ruleId: VNX-DOCKER-NNN`. The standard SARIF location fields point to the Dockerfile line:

```bash
# Every VNX-DOCKER-* finding
jq '.runs[].results[]
    | select(.ruleId | startswith("VNX-DOCKER-"))
    | {
        ruleId,
        file: .locations[0].physicalLocation.artifactLocation.uri,
        line: .locations[0].physicalLocation.region.startLine,
        message: .message.text
      }' .vulnetix/sast.sarif

# One rule's hits across all Dockerfiles
jq '.runs[].results[]
    | select(.ruleId == "VNX-DOCKER-001")' .vulnetix/sast.sarif
```

## The eight Dockerfile rules

Each rule below has a bad pattern, a good pattern, and a reason. Look the rule up on docs.cli.vulnetix.com (`/docs/sast-rules/vnx-docker-NNN/`) for the exact detection logic.

### VNX-DOCKER-001: missing `USER` directive

Default Docker behaviour is to run as `root`. A compromise inside the container then runs as root inside the container's namespaces — privileged enough to break out of many sandboxes, especially with mounted volumes.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["python", "app.py"]
```
{{< /tab >}}
{{< tab name="Good (simple)" >}}
```dockerfile
FROM python:3.12-slim

RUN useradd --create-home --shell /bin/bash --uid 1000 app
WORKDIR /home/app
COPY --chown=app:app . .
USER app
RUN pip install --user -r requirements.txt

CMD ["python", "app.py"]
```
{{< /tab >}}
{{< tab name="Good (distroless)" >}}
```dockerfile
FROM python:3.12-slim AS build
WORKDIR /app
COPY . .
RUN pip install --target=/app/deps -r requirements.txt

FROM gcr.io/distroless/python3-debian12
WORKDIR /app
COPY --from=build /app /app
ENV PYTHONPATH=/app/deps
USER nonroot
CMD ["app.py"]
```
{{< /tab >}}
{{< /tabs >}}

### VNX-DOCKER-002: unpinned `:latest` tag

`FROM debian:latest` resolves to a different image every time you build. Reproducibility and security both suffer — you can't rebuild yesterday's image, and you don't know what's in it.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
FROM debian:latest
```
{{< /tab >}}
{{< tab name="Good (tag pin)" >}}
```dockerfile
FROM debian:12.5-slim
```
{{< /tab >}}
{{< tab name="Good (digest pin)" >}}
```dockerfile
FROM debian@sha256:5f7e9e09786373f47e3036d9fb6bb47cbf1f6d54f3dc7a3a4e0eddd4d1f04f9f
```
{{< /tab >}}
{{< /tabs >}}

Digest pins are immutable and survive registry takeovers; tag pins are mutable but human-readable. Renovate or Dependabot can keep digest pins fresh automatically.

### VNX-DOCKER-003: missing `HEALTHCHECK`

A container without a healthcheck is a black box to the orchestrator — Kubernetes / Compose can't distinguish a hung process from a working one. Failures cascade because nothing replaces a wedged container.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
FROM nginx:1.27
COPY site/ /usr/share/nginx/html/
EXPOSE 80
```
{{< /tab >}}
{{< tab name="Good" >}}
```dockerfile
FROM nginx:1.27
COPY site/ /usr/share/nginx/html/
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost/health || exit 1
```
{{< /tab >}}
{{< /tabs >}}

Kubernetes uses its own readiness/liveness probes (defined in the manifest, not the Dockerfile), but the `HEALTHCHECK` directive still serves Compose, `docker run`, and Swarm.

### VNX-DOCKER-004: uncached package manager layer

`apt-get update` in one layer and `apt-get install` in another means a future build can install against a stale package index — and the layer reuse misses the security patches in the update.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
RUN apt-get update
RUN apt-get install -y curl ca-certificates
```
{{< /tab >}}
{{< tab name="Good" >}}
```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*
```
{{< /tab >}}
{{< /tabs >}}

Combine update + install + cleanup into one `RUN`. `--no-install-recommends` skips optional packages that bloat the image. `rm -rf /var/lib/apt/lists/*` discards the package index after install — cuts the image size by ~30 MB.

### VNX-DOCKER-005: hardcoded secrets in `ENV`

`ENV` values are baked into every layer that uses them — they end up in the image, the registry, and any tarball produced by `docker save`. A secret in `ENV` is a leaked secret the moment the image is pushed.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
ENV DATABASE_URL="postgres://app:hunter2@db.internal/myapp"
ENV NPM_TOKEN="npm_aBcDeFgHiJkLmNoP1234567890qrstuvwxyzabcd"

RUN npm install
```
{{< /tab >}}
{{< tab name="Good (BuildKit secret)" >}}
```dockerfile
# syntax=docker/dockerfile:1.4
FROM node:20
WORKDIR /app
COPY package.json package-lock.json ./

RUN --mount=type=secret,id=npm,target=/root/.npmrc \
    npm ci
```
{{< /tab >}}
{{< tab name="Good (runtime injection)" >}}
```dockerfile
# DATABASE_URL is provided by the orchestrator at runtime,
# not at build time. No ENV declaration in the Dockerfile.
CMD ["node", "server.js"]
```
{{< /tab >}}
{{< /tabs >}}

`docker build --secret id=npm,src=$HOME/.npmrc -t myimage .` — the secret is mounted into the build but not persisted in any layer. For runtime secrets, inject via Kubernetes Secret, Docker Compose `environment`, or `--env-file`.

### VNX-DOCKER-006: privileged port exposure

Ports below 1024 require `CAP_NET_BIND_SERVICE` (or root). A container exposing `EXPOSE 80` typically runs as root specifically to bind it, which compounds the VNX-DOCKER-001 problem.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
FROM nginx
USER nginx
EXPOSE 80
```
{{< /tab >}}
{{< tab name="Good (non-privileged port)" >}}
```dockerfile
FROM nginxinc/nginx-unprivileged:1.27
EXPOSE 8080
```
{{< /tab >}}
{{< tab name="Good (setcap)" >}}
```dockerfile
FROM nginx:1.27
RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx
USER nginx
EXPOSE 80
```
{{< /tab >}}
{{< /tabs >}}

`setcap` grants the binary the specific capability without running as root. `nginx-unprivileged` is a pre-configured variant from the official image team — usually the cleanest answer.

### VNX-DOCKER-007: `ADD` instead of `COPY`

`ADD` does more than `COPY` — it can fetch URLs, and it auto-extracts local tarballs. Both are footguns: the URL fetch has no integrity check by default, and the tarball extraction has historically had path-traversal bugs.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
ADD https://example.com/app.tar.gz /opt/
ADD ./src /app/
```
{{< /tab >}}
{{< tab name="Good (COPY for local)" >}}
```dockerfile
COPY ./src /app/
```
{{< /tab >}}
{{< tab name="Good (ADD with checksum)" >}}
```dockerfile
ADD --checksum=sha256:abc123... https://example.com/app.tar.gz /opt/
```
{{< /tab >}}
{{< /tabs >}}

Modern Docker supports `ADD --checksum=` (BuildKit 22.10+) for verified remote downloads. For local files always use `COPY`.

### VNX-DOCKER-008: unoptimised `RUN`

Each `RUN` produces a layer. Many small layers = larger image, longer push/pull times, more attack surface in the registry.

{{< tabs >}}
{{< tab name="Bad" >}}
```dockerfile
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y ca-certificates
RUN curl -fsSL https://get.example.com | bash
RUN apt-get clean
```
{{< /tab >}}
{{< tab name="Good" >}}
```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
 && curl -fsSL https://get.example.com | sh \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
```
{{< /tab >}}
{{< /tabs >}}

Combine. Remove build-time tools (`curl` after the install) before exiting the `RUN`. Discard the package index. Avoid `apt-get clean` standalone — it doesn't run in one-layer images.

## Worked example: hardening a root container that needs build-time root

The build needs `apt-get install`, which needs root. The runtime doesn't. Solution: multi-stage.

```dockerfile
# syntax=docker/dockerfile:1.4

# Build stage — root is fine here, the result is thrown away
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && pip install --user --no-cache-dir -r requirements.txt \
 && rm -rf /var/lib/apt/lists/*

# Runtime stage — distroless, non-root, minimal attack surface
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /root/.local /home/nonroot/.local
COPY --chown=nonroot:nonroot . .
ENV PATH=/home/nonroot/.local/bin:$PATH
USER nonroot

HEALTHCHECK --interval=30s CMD ["/home/nonroot/.local/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]

EXPOSE 8080
CMD ["app.py"]
```

Verify:

```bash
docker build -t myapp:test .
docker run --rm myapp:test id        # uid=65532(nonroot)
docker run --rm myapp:test sh        # exec failed — distroless has no shell
```

## Producing the VEX

Dockerfile findings (VNX-DOCKER-*) go to **OpenVEX** — the subject is your image's tag / digest. If you also run a separate image scanner against the built image and get base-image CVEs, those are SCA findings against `pkg:apk/...` / `pkg:deb/...` PURLs and go to CycloneDX VEX (see the [SCA page](../sca/)).

{{< outcome type="openvex" >}}
```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yourorg/yourrepo/vex/2026-05-14-docker-001.json",
  "author": "developer@example.com",
  "timestamp": "2026-05-14T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "VNX-DOCKER-001",
        "description": "Container runs as root — no USER directive. See https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-001/"
      },
      "products": [{
        "@id": "ghcr.io/yourorg/myapp:2.3.0",
        "identifiers": { "purl": "pkg:oci/myapp@sha256:abc123...?repository_url=ghcr.io/yourorg" }
      }],
      "status": "fixed",
      "action_statement": "Dockerfile restructured as multi-stage build. Runtime stage uses gcr.io/distroless/python3-debian12:nonroot with USER nonroot. Verified docker run --rm myapp:test id returns uid=65532. See MR !67."
    }
  ]
}
```
{{< /outcome >}}
