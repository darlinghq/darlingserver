#!/usr/bin/env python3
# Usage: extract-function.py <call.cpp> <out.inc>
# Writes Call::callFromMessage verbatim from the given call.cpp, so a test can compile the real body.
import sys

src, out = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith("std::shared_ptr<DarlingServer::Call> DarlingServer::Call::callFromMessage("))
depth, block, opened = 0, [], False
for l in lines[start:]:
    block.append(l)
    depth += l.count("{") - l.count("}")
    opened = opened or "{" in l
    if opened and depth == 0:
        break
open(out, "w").write("\n".join(block) + "\n")
