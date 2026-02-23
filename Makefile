.PHONY: test test-build

test-build:
	docker build -f Dockerfile.test -t lua-resty-ja4-test .

test: test-build
	docker run --rm --init lua-resty-ja4-test

test-verbose: test-build
	docker run --rm --init lua-resty-ja4-test prove -v -r t/

# --- E2E Tests ---
.PHONY: e2e e2e-clean

e2e:
	docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests-1.27 nginx-1.27 tests-1.27
	docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests-1.29 nginx-1.29 tests-1.29

e2e-clean:
	docker compose -f e2e/docker-compose.e2e.yml down --rmi local --volumes --remove-orphans

# --- Performance Analysis ---
.PHONY: bench-build jit-trace jit-dump jit-profile jit-alloc jit-bench jit-all jit-report

BENCH_IMAGE = lua-resty-ja4-bench
BENCH_RUN = docker run --rm $(BENCH_IMAGE) resty -I /app/lib -I /app/bench

bench-build:
	docker build -f Dockerfile.bench -t $(BENCH_IMAGE) .

jit-bench: bench-build
	$(BENCH_RUN) /app/bench/microbench.lua

jit-alloc: bench-build
	$(BENCH_RUN) /app/bench/alloc_track.lua

jit-trace: bench-build
	$(BENCH_RUN) /app/bench/jit_trace.lua

jit-profile: bench-build
	$(BENCH_RUN) /app/bench/jit_profile.lua

jit-dump: bench-build
	$(BENCH_RUN) /app/bench/jit_dump.lua

jit-all: bench-build
	@echo "=== Running all JIT analysis targets ==="
	$(BENCH_RUN) /app/bench/microbench.lua
	$(BENCH_RUN) /app/bench/alloc_track.lua
	$(BENCH_RUN) /app/bench/jit_trace.lua
	$(BENCH_RUN) /app/bench/jit_profile.lua
	@echo ""
	@echo "=== All analyses complete ==="

jit-report: bench-build
	@mkdir -p bench/reports
	$(BENCH_RUN) /app/bench/microbench.lua > bench/reports/bench.txt 2>&1
	$(BENCH_RUN) /app/bench/alloc_track.lua > bench/reports/alloc.txt 2>&1
	$(BENCH_RUN) /app/bench/jit_trace.lua > bench/reports/trace.txt 2>&1
	$(BENCH_RUN) /app/bench/jit_profile.lua > bench/reports/profile.txt 2>&1
	$(BENCH_RUN) /app/bench/jit_dump.lua > bench/reports/dump.txt 2>&1
	@echo "Reports saved to bench/reports/"
