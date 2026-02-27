# E2E Pre-built Image Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Use official Docker image for OpenResty 1.27 E2E tests, build only 1.29 from source, with separate Makefile targets.

**Architecture:** Two docker-compose files — one for 1.27 (pre-built `openresty/openresty:1.27.1.2-11-jammy`) and one for 1.29 (built via `Dockerfile.openresty`). Simplified service names (`nginx`, `tests`) since each file is version-specific.

**Tech Stack:** Docker Compose, Make, GitHub Actions

**Design doc:** `docs/plans/2026-02-27-e2e-prebuilt-image-design.md`

---

### Task 1: Rewrite docker-compose.e2e.yml for 1.27 pre-built image

**Files:**
- Modify: `e2e/docker-compose.e2e.yml`

**Step 1: Replace the compose file contents**

Replace the entire file with:

```yaml
services:
  nginx:
    image: openresty/openresty:1.27.1.2-11-jammy
    volumes:
      - ../lib:/app/lib:ro
      - ./nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
    command:
      - /bin/sh
      - -c
      - |
        mkdir -p /etc/nginx
        openssl req -x509 -newkey rsa:2048 \
          -keyout /etc/nginx/server.key -out /etc/nginx/server.crt \
          -days 365 -nodes -subj '/CN=ja4-e2e' 2>/dev/null
        openresty -g 'daemon off;'
    healthcheck:
      test: ["CMD", "curl", "-kf", "https://localhost/health"]
      interval: 2s
      timeout: 5s
      retries: 10
      start_period: 5s

  tests:
    build:
      context: ..
      dockerfile: e2e/Dockerfile.tests
    depends_on:
      nginx:
        condition: service_healthy
    environment:
      - NGINX_HOST=nginx
      - NGINX_PORT=443
      - NGINX_RAW_PORT=8443
```

Key changes from current file:
- Service `nginx-1.27` → `nginx` (simplified name)
- `build:` block → `image: openresty/openresty:1.27.1.2-11-jammy` (no build)
- Service `tests-1.27` → `tests`, env `NGINX_HOST=nginx`
- Removed all 1.29 services (moved to separate file)

**Step 2: Verify syntax**

Run: `docker compose -f e2e/docker-compose.e2e.yml config --quiet`
Expected: No output (valid YAML)

---

### Task 2: Create docker-compose.e2e-1.29.yml for source-built 1.29

**Files:**
- Create: `e2e/docker-compose.e2e-1.29.yml`

**Step 1: Create the new compose file**

```yaml
services:
  nginx:
    build:
      context: ..
      dockerfile: e2e/Dockerfile.openresty
      args:
        RESTY_VERSION: "1.29.2.1"
        RESTY_J: "4"
    volumes:
      - ../lib:/app/lib:ro
      - ./nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
    command:
      - /bin/sh
      - -c
      - |
        mkdir -p /etc/nginx
        openssl req -x509 -newkey rsa:2048 \
          -keyout /etc/nginx/server.key -out /etc/nginx/server.crt \
          -days 365 -nodes -subj '/CN=ja4-e2e' 2>/dev/null
        openresty -g 'daemon off;'
    healthcheck:
      test: ["CMD", "curl", "-kf", "https://localhost/health"]
      interval: 2s
      timeout: 5s
      retries: 10
      start_period: 5s

  tests:
    build:
      context: ..
      dockerfile: e2e/Dockerfile.tests
    depends_on:
      nginx:
        condition: service_healthy
    environment:
      - NGINX_HOST=nginx
      - NGINX_PORT=443
      - NGINX_RAW_PORT=8443
```

**Step 2: Verify syntax**

Run: `docker compose -f e2e/docker-compose.e2e-1.29.yml config --quiet`
Expected: No output (valid YAML)

---

### Task 3: Update Makefile targets

**Files:**
- Modify: `Makefile` (lines 12-20)

**Step 1: Replace the E2E section**

Replace lines 12-20 (the `# --- E2E Tests ---` section) with:

```makefile
# --- E2E Tests ---
.PHONY: e2e e2e-1.29 e2e-clean

e2e:
	docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests

e2e-1.29:
	docker compose -f e2e/docker-compose.e2e-1.29.yml up --build --abort-on-container-exit --exit-code-from tests

e2e-clean:
	docker compose -f e2e/docker-compose.e2e.yml down --rmi local --volumes --remove-orphans
	docker compose -f e2e/docker-compose.e2e-1.29.yml down --rmi local --volumes --remove-orphans
```

Key changes:
- `e2e` now runs only 1.27 (one compose-up, no version-suffixed service names)
- New `e2e-1.29` target for 1.29
- `e2e-clean` cleans both compose files
- Service names `tests-1.27`/`nginx-1.27` → `tests`/`nginx` (match new compose files)

---

### Task 4: Update CI workflow — e2e-bench.yml

**Files:**
- Modify: `.github/workflows/e2e-bench.yml`

**Step 1: Update the E2E job steps**

Replace the e2e job steps (lines 14-35) with:

```yaml
    steps:
      - uses: actions/checkout@v4

      - name: Run E2E tests (OpenResty 1.27)
        run: >
          docker compose -f e2e/docker-compose.e2e.yml up
          --build --abort-on-container-exit --exit-code-from tests

      - name: Clean up 1.27 containers
        if: always()
        run: docker compose -f e2e/docker-compose.e2e.yml down --volumes --remove-orphans

      - name: Run E2E tests (OpenResty 1.29)
        run: >
          docker compose -f e2e/docker-compose.e2e-1.29.yml up
          --build --abort-on-container-exit --exit-code-from tests

      - name: Clean up 1.29 containers
        if: always()
        run: docker compose -f e2e/docker-compose.e2e-1.29.yml down --volumes --remove-orphans
```

Changes: separate compose files, service names `tests` instead of `tests-1.27`/`tests-1.29`.

---

### Task 5: Update CI workflow — release.yml

**Files:**
- Modify: `.github/workflows/release.yml`

**Step 1: Update the test job E2E steps**

Replace the E2E steps in the test job (lines 46-64) with:

```yaml
      - name: Run E2E tests (OpenResty 1.27)
        run: >
          docker compose -f e2e/docker-compose.e2e.yml up
          --build --abort-on-container-exit --exit-code-from tests

      - name: Clean up 1.27 containers
        if: always()
        run: docker compose -f e2e/docker-compose.e2e.yml down --volumes --remove-orphans

      - name: Run E2E tests (OpenResty 1.29)
        run: >
          docker compose -f e2e/docker-compose.e2e-1.29.yml up
          --build --abort-on-container-exit --exit-code-from tests

      - name: Clean up 1.29 containers
        if: always()
        run: docker compose -f e2e/docker-compose.e2e-1.29.yml down --volumes --remove-orphans
```

---

### Task 6: Run E2E tests (1.27) and verify

**Step 1: Run 1.27 E2E**

Run: `make e2e`
Expected: All 47 tests pass using the pre-built image (no OpenSSL/PCRE2/OpenResty compilation)

**Step 2: Clean up**

Run: `make e2e-clean`

---

### Task 7: Run E2E tests (1.29) and verify

**Step 1: Run 1.29 E2E**

Run: `make e2e-1.29`
Expected: All 47 tests pass (builds from source as before)

**Step 2: Clean up**

Run: `make e2e-clean`

---

### Task 8: Commit

**Step 1: Stage and commit**

```bash
git add e2e/docker-compose.e2e.yml e2e/docker-compose.e2e-1.29.yml Makefile .github/workflows/e2e-bench.yml .github/workflows/release.yml
git commit -m "refactor(e2e): use pre-built image for 1.27, separate compose files

Use official openresty/openresty:1.27.1.2-11-jammy image instead of
building from source. Split into separate compose files and Makefile
targets: 'make e2e' (1.27, fast) and 'make e2e-1.29' (built from source)."
```
