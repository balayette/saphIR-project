#pragma once

#include "ass/instr.hh"

namespace backend::opt
{
void peephole(std::vector<assem::rinstr> &instrs);
} // namespace backend::opt
