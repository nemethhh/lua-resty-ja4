-- bench/jit_dump.lua
-- Full IR (Intermediate Representation) and machine code dump.
-- Very verbose — pipe output to a file or pager.
-- Usage: make jit-dump 2>&1 | less
--        make jit-dump > dump.txt 2>&1

local ja4 = require("resty.ja4")
local ja4h = require("resty.ja4h")
local utils = require("resty.ja4.utils")
local testdata = require("testdata")

local TMPFILE = "/tmp/jit_dump_output.txt"
local profile = testdata.typical

io.write("\n=== JIT IR + Machine Code Dump ===\n")
io.write("Profile: typical\n")
io.write("Flags: +tim (trace events, IR, machine code)\n\n")

-- Capture dump to file, then display
local jitdump = require("jit.dump")
jitdump.start("+tim", TMPFILE)

for _ = 1, 200 do ja4.build(profile.ja4) end
for _ = 1, 200 do ja4h.build(profile.ja4h) end
for _ = 1, 200 do utils.sha256_hex12("dump_test") end

jitdump.off()

local f = io.open(TMPFILE)
if f then
    io.write(f:read("*a") or "")
    f:close()
end

io.write("\n--- Guide ---\n\n")
io.write("  ---- TRACE N start file:line  new trace compilation\n")
io.write("  .... SNAP #N ...              snapshot (deopt point)\n")
io.write("  ---- TRACE N IR               SSA IR operations\n")
io.write("  ---- TRACE N mcode NNN        machine code (NNN bytes)\n")
io.write("\n  IR ops to watch:\n")
io.write("    CALLN/CALLS  function calls (potential overhead)\n")
io.write("    SNEW/BUFPUT  string allocations\n")
io.write("    TNEW/TDUP    table allocations\n")
io.write("    GCSTEP       GC step (allocation pressure)\n\n")
