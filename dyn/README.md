# Dynamic binary translator

This uses the lifter to translate ARM64 binaries to x86 and execute them.

## Features

* Enough ARM64 instructions and syscalls to run basic musl programs
* Fully deterministic
* Instrumentation of memory reads and writes
* Instrumentation on basic block entry
* Single stepping
* A memory management unit
* Fast reset of the MMU with dirty page tracking and Copy-on-Write
