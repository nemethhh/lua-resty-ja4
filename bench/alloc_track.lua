-- bench/alloc_track.lua
-- Allocation tracking for JA4/JA4H functions.
-- Stops GC during measurement to capture net allocation per call.

local ja4 = require("resty.ja4")
local ja4h = require("resty.ja4h")
local utils = require("resty.ja4.utils")
local testdata = require("testdata")

local WARMUP = 100
local ITERS = 1000

local function measure_alloc(fn)
    for _ = 1, WARMUP do fn() end

    collectgarbage("collect")
    collectgarbage("stop")

    local before = collectgarbage("count")
    for _ = 1, ITERS do fn() end
    local after = collectgarbage("count")

    collectgarbage("restart")
    collectgarbage("collect")

    local delta_kb = after - before
    return (delta_kb * 1024) / ITERS
end

local W1, W2, W3, W4 = 28, 14, 14, 10

io.write("\n=== Allocation Analysis ===\n")
io.write(string.format("Warmup: %d | Measured: %d iterations (GC stopped)\n\n", WARMUP, ITERS))

for _, pname in ipairs(testdata.profiles) do
    local profile = testdata[pname]
    io.write(string.format("--- Profile: %s ---\n\n", pname))

    io.write(string.format("%-" .. W1 .. "s%-" .. W2 .. "s%s\n",
        "Function", "Bytes/call", "Pressure"))
    io.write(string.rep("-", W1 + W2 + W4) .. "\n")

    local function report(label, fn)
        local bpc = measure_alloc(fn)
        local pressure
        if bpc < 64 then pressure = "minimal"
        elseif bpc < 256 then pressure = "low"
        elseif bpc < 1024 then pressure = "moderate"
        else pressure = "HIGH"
        end
        io.write(string.format("%-" .. W1 .. "s%-" .. W2 .. "s%s\n",
            label, string.format("%.0f", bpc), pressure))
    end

    report("ja4.build()", function() ja4.build(profile.ja4) end)
    report("ja4h.build()", function() ja4h.build(profile.ja4h) end)
    report("sha256_hex12()", function() utils.sha256_hex12("test") end)

    if profile.raw_sig_algs then
        report("parse_sig_algs()", function() utils.parse_sig_algs(profile.raw_sig_algs) end)
    end
    if profile.cookie_str then
        report("parse_cookies()", function() utils.parse_cookies(profile.cookie_str) end)
    end
    if profile.raw_headers then
        report("parse_raw_header_names()", function() utils.parse_raw_header_names(profile.raw_headers) end)
    end

    -- Heap growth test with GC enabled
    collectgarbage("collect")
    local heap_before = collectgarbage("count")
    for _ = 1, ITERS do
        ja4.build(profile.ja4)
        ja4h.build(profile.ja4h)
    end
    local heap_after = collectgarbage("count")

    io.write(string.format(
        "\n  Heap after %d full cycles (GC on): %.1f KB (delta: %+.1f KB)\n\n",
        ITERS, heap_after, heap_after - heap_before))
end
