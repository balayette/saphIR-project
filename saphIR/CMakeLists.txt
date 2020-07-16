add_library(IR STATIC
        src/mach/amd64/amd64-access.cc
        src/mach/amd64/amd64-target.cc
        src/mach/amd64/amd64-common.cc
        src/mach/amd64/amd64-codegen.cc
        src/mach/amd64/amd64-instr.cc
        src/mach/aarch64/aarch64-instr.cc
        src/mach/aarch64/aarch64-target.cc
        src/mach/aarch64/aarch64-common.cc
        src/mach/aarch64/aarch64-access.cc
        src/mach/aarch64/aarch64-codegen.cc
        src/mach/access.cc
        src/mach/target.cc
        src/ir/ir.cc
        src/ir/ops.cc
        src/ir/types.cc
        src/ir/canon/linearize.cc
        src/ir/canon/bb.cc
        src/ir/canon/trace.cc
        src/ir/visitors/default-ir-visitor.cc
        src/ir/visitors/ir-pretty-printer.cc
        src/ir/visitors/ir-cloner-visitor.cc
        src/ir/visitors/ir-binop-optimizer.cc
        src/ir/visitors/ir-arith-optimizer.cc
        src/ir/visitors/ir-cnst-obfuscator.cc
        src/ass/instr.cc
        src/backend/cfg.cc
        src/backend/liveness.cc
        src/backend/regalloc.cc
        src/backend/color.cc
)

target_include_directories(IR
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(IR
        PUBLIC utils
)
