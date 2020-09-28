#include "dyn/unicorn-emu.hh"
#include "utils/misc.hh"

namespace dyn
{
unicorn_emu::unicorn_emu(utils::mapped_file &file, uint64_t stack_addr,
			 uint64_t stack_sz)
    : base_emu(file)
{
	ASSERT(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc_) == UC_ERR_OK,
	       "Couldn't init unicorn");

	elf_map_ = map_elf();

	ASSERT(uc_mem_map(uc_, stack_addr, stack_sz,
			  UC_PROT_READ | UC_PROT_WRITE)
		       == UC_ERR_OK,
	       "Couldn't map the stack");
	reg_write(UC_ARM64_REG_SP, stack_addr + stack_sz);
	reg_write(UC_ARM64_REG_NZCV, lifter::Z << 28);

	state_.tpidr_el0 = 0;

	pc_ = bin_.ehdr().entry();
}

std::pair<uint64_t, size_t> unicorn_emu::singlestep()
{
	int ret = uc_emu_start(uc_, pc_, 0, 0, 1);
	ASSERT(ret == UC_ERR_OK, "Couldn't emulate instruction ({})", ret);

	update_state();
	return std::make_pair(reg_read(UC_ARM64_REG_PC), 1);
}

uint64_t unicorn_emu::push(size_t val) { return push(&val, sizeof(val)); }

uint64_t unicorn_emu::push(const void *data, size_t sz)
{
	uint64_t sp = reg_read(UC_ARM64_REG_SP);

	sp -= sz;
	mem_write(sp, data, sz);

	reg_write(UC_ARM64_REG_SP, sp);

	return sp;
}

void unicorn_emu::mem_write(size_t addr, const void *data, size_t sz)
{
	ASSERT(uc_mem_write(uc_, addr, data, sz) == UC_ERR_OK,
	       "Couldn't write {:#x} bytes to {:#x}", sz, addr);
}

uint64_t unicorn_emu::reg_read(int reg)
{
	uint64_t ret = 0;
	ASSERT(uc_reg_read(uc_, reg, &ret) == UC_ERR_OK,
	       "Couldn't read value of register {}", reg);

	return ret;
}

void unicorn_emu::reg_write(int reg, uint64_t val)
{
	ASSERT(uc_reg_write(uc_, reg, &val) == UC_ERR_OK,
	       "Couldn't write value {:#x} to register {}", val, reg);
	update_state();
}

void unicorn_emu::align_stack(size_t align)
{
	reg_write(UC_ARM64_REG_SP,
		  ROUND_DOWN(reg_read(UC_ARM64_REG_SP), align));
}

void unicorn_emu::update_state()
{
	int all_regs[] = {
		UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,
		UC_ARM64_REG_X3,  UC_ARM64_REG_X4,  UC_ARM64_REG_X5,
		UC_ARM64_REG_X6,  UC_ARM64_REG_X7,  UC_ARM64_REG_X8,
		UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
		UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14,
		UC_ARM64_REG_X15, UC_ARM64_REG_X16, UC_ARM64_REG_X17,
		UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
		UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
		UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
		UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
		UC_ARM64_REG_X30, UC_ARM64_REG_SP,
	};

	for (size_t i = 0; i < sizeof(all_regs) / sizeof(all_regs[0]); i++)
		state_.regs[i] = reg_read(all_regs[i]);

	state_.nzcv = reg_read(UC_ARM64_REG_NZCV) >> 28;
}

void *unicorn_emu::map_elf()
{
	size_t min = ~0;
	size_t max = 0;

	for (const auto &segment : bin_.phdrs()) {
		if (segment.type() != PT_LOAD)
			continue;
		if (segment.vaddr() < min)
			min = segment.vaddr();
		if (segment.vaddr() + segment.memsz() > max)
			max = segment.vaddr() + segment.memsz();
	}

	min = ROUND_DOWN(min, 4096);
	max = ROUND_UP(max, 4096);
	size_t size = max - min;
	size_t map = min;

	ASSERT(uc_mem_map(uc_, min, size, UC_PROT_ALL) == UC_ERR_OK,
	       "Couldn't map elf binary in Unicorn");

	for (const auto &segment : bin_.phdrs()) {
		if (segment.type() != PT_LOAD)
			continue;

		auto contents = segment.contents(file_).data();

		ASSERT(uc_mem_write(uc_, map + (segment.vaddr() - min),
				    contents, segment.filesz())
			       == UC_ERR_OK,
		       "Couldn't copy contents of segment");
	}

	return (void *)map;
}
} // namespace dyn
