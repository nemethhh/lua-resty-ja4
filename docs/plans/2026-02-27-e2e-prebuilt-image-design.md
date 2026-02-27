# E2E: Pre-built OpenResty 1.27 Image + Separate Commands

**Date:** 2026-02-27

## Problem

Both OpenResty 1.27 and 1.29 E2E tests build from source via `Dockerfile.openresty`, compiling OpenSSL + PCRE2 + OpenResty. This is slow and unnecessary for 1.27 since official Docker images exist.

## Solution

Use the official `openresty/openresty:1.27.1.2-11-jammy` image for 1.27 tests. Keep building 1.29 from source (no official image exists). Split into separate compose files and Makefile targets.

## Verification

The official 1.27 image uses OpenSSL 3.5.5 with identical configure arguments (http_v2, http_v3, ssl, etc.) and has `curl` available for healthchecks — confirmed as a drop-in replacement.

## Docker Compose Files

### `e2e/docker-compose.e2e.yml` (OpenResty 1.27)

- `nginx` service: `image: openresty/openresty:1.27.1.2-11-jammy` (no build)
- `tests` service: builds `Dockerfile.tests`, depends on `nginx`
- Simplified service names: `nginx`, `tests` (no version suffix)

### `e2e/docker-compose.e2e-1.29.yml` (OpenResty 1.29)

- `nginx` service: builds from `Dockerfile.openresty` with `RESTY_VERSION: "1.29.2.1"`
- `tests` service: builds `Dockerfile.tests`, depends on `nginx`
- Same simplified naming: `nginx`, `tests`

## Makefile Targets

```makefile
e2e:        # 1.27 pre-built image — fast
e2e-1.29:   # 1.29 built from source — slow
e2e-clean:  # cleans both
```

## CI Workflow

`e2e-bench.yml` updated to reference the new compose file names.

## Unchanged

- `Dockerfile.openresty` — still needed for 1.29
- `Dockerfile.tests`, `nginx.conf`, all test files — no changes
