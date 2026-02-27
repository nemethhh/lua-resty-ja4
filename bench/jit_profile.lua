-- bench/jit_profile.lua
-- CPU sampling profiler using jit.p.
-- Shows where CPU time is spent across functions and lines.

local ja4 = require("resty.ja4")
local ja4h = require("resty.ja4h")
local utils = require("resty.ja4.utils")
local testdata = require("testdata")

local WARMUP = 500
local ITERS = 500000

local profile = testdata.typical

io.write("\n=== CPU Profile (jit.p) ===\n")
io.write(string.format("Profile: typical | Warmup: %d | Measured: %d iterations\n\n", WARMUP, ITERS))

-- Warmup: let JIT compile everything first
for _ = 1, WARMUP do
    ja4.build(profile.ja4)
    ja4h.build(profile.ja4h)
    utils.parse_alpn(profile.raw_alpn)
    utils.parse_sig_algs(profile.raw_sig_algs)
    utils.parse_cookies_into(profile.cookie_str, {}, {})
    utils.parse_raw_header_names(profile.raw_headers)
end

local jitp = require("jit.p")

-- Profile 1: function-level, build() functions
local tmp1 = "/tmp/jitp_build_f.txt"
io.write("--- Function-level: ja4.build() + ja4h.build() ---\n\n")
jitp.start("f", tmp1)
for _ = 1, ITERS do
    ja4.build(profile.ja4)
    ja4h.build(profile.ja4h)
end
jitp.stop()
local f1 = io.open(tmp1)
if f1 then io.write(f1:read("*a") or ""); f1:close() end
io.write("\n")

-- Profile 2: line-level, build() functions
local tmp2 = "/tmp/jitp_build_l.txt"
io.write("--- Line-level: ja4.build() + ja4h.build() ---\n\n")
jitp.start("l", tmp2)
for _ = 1, ITERS do
    ja4.build(profile.ja4)
    ja4h.build(profile.ja4h)
end
jitp.stop()
local f2 = io.open(tmp2)
if f2 then io.write(f2:read("*a") or ""); f2:close() end
io.write("\n")

-- Profile 3: function-level, utility functions
local tmp3 = "/tmp/jitp_utils_f.txt"
io.write("--- Function-level: utility functions ---\n\n")
jitp.start("f", tmp3)
for _ = 1, ITERS do
    utils.parse_alpn(profile.raw_alpn)
    utils.parse_sig_algs(profile.raw_sig_algs)
    utils.parse_cookies_into(profile.cookie_str, {}, {})
    utils.parse_raw_header_names(profile.raw_headers)
end
jitp.stop()
local f3 = io.open(tmp3)
if f3 then io.write(f3:read("*a") or ""); f3:close() end

io.write("\n--- Guide ---\n\n")
io.write("  Higher % = more CPU time in that function/line.\n")
io.write("  [C]  = C function (FFI, built-in)\n")
io.write("  [G]  = garbage collector — should be ~0%%\n")
io.write("  [I]  = interpreter (not JIT-compiled) — investigate if high\n")
io.write("  [J]  = JIT-compiled machine code — ideal for hot paths\n\n")
