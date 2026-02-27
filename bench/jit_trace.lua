-- bench/jit_trace.lua
-- JIT trace analysis using jit.v.
-- Shows what gets compiled and what aborts (NYI = Not Yet Implemented).

local ja4 = require("resty.ja4")
local ja4h = require("resty.ja4h")
local utils = require("resty.ja4.utils")
local testdata = require("testdata")

local ITERS = 200
local TMPFILE = "/tmp/jit_trace_output.txt"

local profile = testdata.typical

io.write("\n=== JIT Trace Analysis (jit.v) ===\n")
io.write(string.format("Profile: typical | Iterations: %d\n", ITERS))
io.write("Running all functions to trigger JIT compilation...\n\n")

-- Capture jit.v output to file for clean display
local jitv = require("jit.v")
jitv.start(TMPFILE)

for _ = 1, ITERS do ja4.build(profile.ja4) end
for _ = 1, ITERS do ja4h.build(profile.ja4h) end
for _ = 1, ITERS do utils.parse_alpn(profile.raw_alpn) end
for _ = 1, ITERS do utils.parse_sig_algs(profile.raw_sig_algs) end
for _ = 1, ITERS do utils.parse_cookies_into(profile.cookie_str, {}, {}) end
for _ = 1, ITERS do utils.parse_raw_header_names(profile.raw_headers) end
for _ = 1, ITERS do utils.parse_alpn(profile.raw_alpn) end

jitv.off()

-- Read captured output
local f = io.open(TMPFILE)
local content = ""
if f then
    content = f:read("*a") or ""
    f:close()
end

if content == "" then
    io.write("(no trace events recorded)\n\n")
else
    io.write("--- Trace events ---\n\n")
    io.write(content)
    io.write("\n")
end

-- Parse and summarize
local compiled, aborted = 0, 0
local nyi_reasons = {}
for line in content:gmatch("[^\n]+") do
    if line:match("^%[TRACE%s+%d+") and not line:match("^%[TRACE%s+%d+%s+%-%-%-") then
        compiled = compiled + 1
    end
    if line:match("^%[TRACE%s+%-%-%-") then
        aborted = aborted + 1
        local reason = line:match("-- (.+)%]$")
        if reason then
            nyi_reasons[reason] = (nyi_reasons[reason] or 0) + 1
        end
    end
end

io.write("--- Summary ---\n\n")
io.write(string.format("  Traces compiled: %d\n", compiled))
io.write(string.format("  Traces aborted:  %d\n", aborted))

if next(nyi_reasons) then
    io.write("\n  Abort reasons:\n")
    for reason, count in pairs(nyi_reasons) do
        io.write(string.format("    %dx  %s\n", count, reason))
    end
end

io.write("\n--- Guide ---\n\n")
io.write("  [TRACE N file:line loop]      compiled loop trace (good)\n")
io.write("  [TRACE N file:line -> M]      trace stitched to trace M (good)\n")
io.write("  [TRACE --- file:line -- ...]  trace ABORTED (investigate)\n")
io.write("\n  Common abort reasons:\n")
io.write("    NYI: <op>        LuaJIT cannot compile this operation\n")
io.write("    leaving loop     loop exits compiled region\n")
io.write("    blacklisted      trace failed too many times\n")
io.write("\n  Good: all hot paths compiled. Bad: NYI on hot paths.\n\n")
