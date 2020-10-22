#include "fuzz/harness.hh"

namespace fuzz
{
void harness::setup(dyn::base_emu &emu) { emu.setup(); }
} // namespace fuzz
