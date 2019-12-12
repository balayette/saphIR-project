#pragma once

#include "mach/frame.hh"
#include "ass/instr.hh"
#include "ir/ir.hh"
#include <vector>

namespace mach
{
std::vector<assem::instr> codegen(frame::frame &f, ir::tree::rnodevec instrs);
} // namespace mach
