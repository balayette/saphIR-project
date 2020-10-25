#include "dyn/unicorn-emu.hh"
#include "utils/misc.hh"

namespace dyn
{
void mem_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
	    int64_t value, void *user_data)
{
	auto *emu = static_cast<unicorn_emu *>(user_data);

	if (type == UC_MEM_READ) {
		ASSERT(uc_mem_read(uc, address, &value, size) == UC_ERR_OK,
		       "Couldn't read");
		emu->dispatch_read_cb(address, size, value);
	} else if (type == UC_MEM_WRITE)
		emu->dispatch_write_cb(address, size, value);
	else
		UNREACHABLE("Unimplemented callback");
}

unicorn_emu::unicorn_emu(utils::mapped_file &file, const emu_params &p)
    : base_emu(file, p)
{
	ASSERT(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc_) == UC_ERR_OK,
	       "Couldn't init unicorn");
}

void unicorn_emu::reset()
{
	base_emu::reset();
	state_to_unicorn();
}

void unicorn_emu::add_mem_read_callback(mem_read_callback cb, void *data)
{
	auto needs_register = mem_read_cbs_.size() == 0;

	mem_read_cbs_.push_back({cb, data});

	if (!needs_register)
		return;

	ASSERT(uc_hook_add(uc_, &mem_read_hdl_, UC_HOOK_MEM_READ,
			   reinterpret_cast<void *>(mem_cb), this, 1, 0)
		       == UC_ERR_OK,
	       "Couldn't add read hook");
}

void unicorn_emu::add_mem_write_callback(mem_write_callback cb, void *data)
{
	auto needs_register = mem_write_cbs_.size() == 0;

	mem_write_cbs_.push_back({cb, data});

	if (!needs_register)
		return;

	ASSERT(uc_hook_add(uc_, &mem_write_hdl_, UC_HOOK_MEM_WRITE,
			   reinterpret_cast<void *>(mem_cb), this, 1, 0)
		       == UC_ERR_OK,
	       "Couldn't add write hook");
}

std::pair<uint64_t, size_t> unicorn_emu::singlestep()
{
	int ret = uc_emu_start(uc_, pc_, 0, 0, 1);
	unicorn_to_state();

	if (ret == UC_ERR_OK)
		return std::make_pair(ureg_read(UC_ARM64_REG_PC), 1);

	ASSERT(ret == UC_ERR_EXCEPTION,
	       "Couldn't emulate instruction at {:#x} ({})", pc_, ret);

	/*
	 * When unicorn exits with UC_ERR_EXCEPTION, we assume that it was
	 * caused by a svc #0 instruction. Any other instruction that would
	 * cause an exception would stop execution of the saphIR-backed emulator
	 * anyways
	 */

	syscall();
	state_to_unicorn();

	return std::make_pair(ureg_read(UC_ARM64_REG_PC), 1);
}

void unicorn_emu::mem_map(uint64_t guest_addr, size_t length, int prot,
			  int flags, int fd, off_t offset)
{
	(void)flags;

	uc_mem_map(uc_, guest_addr, length, prot);
	if (fd != -1) {
		lseek(fd, offset, SEEK_SET);
		for (size_t i = 0; i < length; i++) {
			uint8_t buf;
			read(fd, &buf, sizeof(buf));
			mem_write(guest_addr + i * sizeof(buf), &buf,
				  sizeof(buf));
		}
	}
}

void unicorn_emu::mem_write(size_t guest_addr, const void *data, size_t sz)
{
	ASSERT(uc_mem_write(uc_, guest_addr, data, sz) == UC_ERR_OK,
	       "Couldn't write {:#x} bytes to {:#x}", sz, guest_addr);
}


void unicorn_emu::mem_read(void *dst, size_t guest_addr, size_t sz)
{
	ASSERT(uc_mem_read(uc_, guest_addr, dst, sz) == UC_ERR_OK,
	       "Couldn't read {:#x} bytes from {:#x}", sz, guest_addr);
}

uint64_t unicorn_emu::ureg_read(int reg)
{
	uint64_t ret = 0;
	ASSERT(uc_reg_read(uc_, reg, &ret) == UC_ERR_OK,
	       "Couldn't read value of register {}", reg);

	return ret;
}

void unicorn_emu::ureg_write(int reg, uint64_t val)
{
	ASSERT(uc_reg_write(uc_, reg, &val) == UC_ERR_OK,
	       "Couldn't write value {:#x} to register {}", val, reg);
}

void unicorn_emu::reg_write(mach::aarch64::regs r, uint64_t val)
{
	base_emu::reg_write(r, val);
	state_to_unicorn();
}

void unicorn_emu::unicorn_to_state()
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
		state_.regs[i] = ureg_read(all_regs[i]);

	state_.nzcv = ureg_read(UC_ARM64_REG_NZCV) >> 28;
	state_.tpidr_el0 = ureg_read(UC_ARM64_REG_TPIDR_EL0);
}

void unicorn_emu::state_to_unicorn()
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
		ureg_write(all_regs[i], state_.regs[i]);

	ureg_write(UC_ARM64_REG_NZCV, state_.nzcv << 28);
	ureg_write(UC_ARM64_REG_TPIDR_EL0, state_.tpidr_el0);
}
} // namespace dyn
