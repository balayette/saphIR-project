#include "lifter/lifter.hh"
#include <keystone/keystone.h>

const char *code =
	"mov x1, x0\n"
	"mov x0, x1\n"
	"mov x2, #123\n"
	"movz x2, #2345, lsl 16\n"
	"add w2, w3, w3, lsl 12\n"
	"add x0, x0, x2\n"
	"add x0, x0, #1\n";

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
	lifter.lift(assembled, size);
}
