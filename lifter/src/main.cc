#include "lifter/lifter.hh"
#include "keystone/keystone.h"

const char *code =
	"mov x1, x0\n"
	"mov x0, x1\n"
	"mov x2, #123\n"
	"movz x2, #2345, lsl 16\n"
	"add w2, w3, w3, lsl 12\n"
	"add x0, x0, x2\n"
	"add x0, x0, #1\n"
	"b #124\n"
	"add x3, x3, x3\n"
	"ret\n";

int main()
{
	ks_engine *ks;
	ASSERT(ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) == KS_ERR_OK,
	       "Couldn't init keystone");

	uint8_t *assembled;
	size_t size, count;
	ASSERT(ks_asm(ks, code, 0, &assembled, &size, &count) == KS_ERR_OK,
	       "Couldn't assemble");

	std::cout << "Assembled to " << size << " bytes, " << count
		  << " instructions\n";

	lifter::lifter lifter;
	lifter::disas disas(assembled, size);

	std::vector<lifter::disas_bb> bbs;
	lifter::disas_bb bb;

	for (size_t i = 0; i < count; i++) {
		auto insn = disas[i];
		bb.append(insn);
		if (bb.complete()) {
			bbs.push_back(bb);
			bb = {};
		}
	}

	ASSERT(bb.insns().size() == 0, "Unfinished basic block");

	for (const auto &bb : bbs) {
		std::cout << "Lifting basic block:\n" << bb.dump() << '\n';
		lifter.lift(bb);
	}
}
