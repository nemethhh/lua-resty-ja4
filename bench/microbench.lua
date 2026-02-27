-- bench/microbench.lua
-- Ops/sec micro-benchmarks for JA4/JA4H functions across all profiles.

local ffi = require("ffi")
pcall(ffi.cdef, [[
struct bench_timespec { long tv_sec; long tv_nsec; };
int clock_gettime(int clk_id, struct bench_timespec *tp);
]])

local ts = ffi.new("struct bench_timespec")
local function now_sec()
    ffi.C.clock_gettime(1, ts)  -- CLOCK_MONOTONIC = 1
    return tonumber(ts.tv_sec) + tonumber(ts.tv_nsec) * 1e-9
end

local ja4 = require("resty.ja4")
local ja4h = require("resty.ja4h")
local utils = require("resty.ja4.utils")
local testdata = require("testdata")

local WARMUP = 100
local ITERS = 100000

local function bench(fn)
    for _ = 1, WARMUP do fn() end
    collectgarbage("collect")

    local t0 = now_sec()
    for _ = 1, ITERS do fn() end
    local elapsed = now_sec() - t0

    return ITERS / elapsed
end

local function fmt_ops(ops)
    if ops >= 1e6 then return string.format("%.2fM ops/s", ops / 1e6)
    elseif ops >= 1e3 then return string.format("%.1fK ops/s", ops / 1e3)
    else return string.format("%.0f ops/s", ops)
    end
end

local W1, W2 = 28, 16  -- column widths

io.write("\n=== Micro-benchmarks ===\n")
io.write(string.format("Warmup: %d | Measured: %d iterations\n\n", WARMUP, ITERS))

-- Header
io.write(string.format("%-" .. W1 .. "s", "Function"))
for _, p in ipairs(testdata.profiles) do
    io.write(string.format("%-" .. W2 .. "s", p))
end
io.write("\n" .. string.rep("-", W1 + W2 * #testdata.profiles) .. "\n")

-- Row helper
local function row(label, make_fn)
    io.write(string.format("%-" .. W1 .. "s", label))
    for _, pname in ipairs(testdata.profiles) do
        local fn = make_fn(testdata[pname])
        if fn then
            io.write(string.format("%-" .. W2 .. "s", fmt_ops(bench(fn))))
        else
            io.write(string.format("%-" .. W2 .. "s", "n/a"))
        end
    end
    io.write("\n")
end

row("ja4.build()", function(p)
    local d = p.ja4
    return function() ja4.build(d) end
end)

row("ja4h.build()", function(p)
    local d = p.ja4h
    return function() ja4h.build(d) end
end)

-- Raw mode (hash=false) benchmarks
ja4.configure({ hash = false })
ja4h.configure({ hash = false })

row("ja4.build() raw", function(p)
    local d = p.ja4
    return function() ja4.build(d) end
end)

row("ja4h.build() raw", function(p)
    local d = p.ja4h
    return function() ja4h.build(d) end
end)

-- Restore hash mode for remaining utility benchmarks
ja4.configure({ hash = true })
ja4h.configure({ hash = true })

-- sha256_to_buf — input-size independent, show once
io.write(string.format("%-" .. W1 .. "s", "sha256_to_buf()"))
local _sha_target = ffi.new("uint8_t[64]")
local sha_ops = bench(function() utils.sha256_to_buf("1301,1302,1303,c02b,c02f", 25, _sha_target, 0) end)
io.write(string.format("%-" .. W2 .. "s", fmt_ops(sha_ops)))
io.write("(input-size independent)\n")

row("parse_sig_algs()", function(p)
    local r = p.raw_sig_algs
    if not r then return nil end
    return function() utils.parse_sig_algs(r) end
end)

row("parse_cookies_into()", function(p)
    local c = p.cookie_str
    if not c then return nil end
    local names, pairs_list = {}, {}
    return function() utils.parse_cookies_into(c, names, pairs_list) end
end)

row("parse_raw_header_names()", function(p)
    local r = p.raw_headers
    if not r then return nil end
    return function() utils.parse_raw_header_names(r) end
end)

row("parse_alpn()", function(p)
    local r = p.raw_alpn
    if not r then return nil end
    return function() utils.parse_alpn(r) end
end)

row("parse_accept_language()", function(p)
    local l = p.ja4h.accept_language
    if not l then return nil end
    return function() utils.parse_accept_language(l) end
end)

io.write("\n")
