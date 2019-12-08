#include "mach/frame.hh"

namespace frame
{
const ::temp::temp &fp()
{
	static ::temp::temp fp(make_unique("rbp").get());
	return fp;
}

const ::temp::temp &rv()
{
	static ::temp::temp rax(make_unique("rax").get());
	return rax;
}

std::ostream &operator<<(std::ostream &os, const access &a)
{
	return a.print(os);
}

std::ostream &operator<<(std::ostream &os, const frame &f)
{
	for (auto a : f.formals_)
		os << a << '\n';
	return os;
}

in_reg::in_reg(::temp::temp reg) : reg_(reg) {}

backend::tree::rexp in_reg::exp() const
{
	return new backend::tree::temp(reg_);
}

std::ostream &in_reg::print(std::ostream &os) const
{
	return os << "in_reg(" << reg_ << ")";
}

in_frame::in_frame(int offt) : offt_(offt) {}

backend::tree::rexp in_frame::exp() const
{
	return new backend::tree::mem(new backend::tree::binop(
		ops::binop::PLUS, new backend::tree::temp(fp()),
		new backend::tree::cnst(offt_)));
}

std::ostream &in_frame::print(std::ostream &os) const
{
	os << "in_frame(" << fp() << " ";
	if (offt_ < 0)
		os << "- " << -offt_;
	else
		os << "+ " << offt_;
	return os << ")";
}

frame::frame(const symbol &s, const std::vector<bool> &args)
    : s_(s), escaping_count_(0), reg_count_(0)
{
	/*
	 * This struct contains a view of where the args should be when
	 * inside the function. The translation for escaping arguments
	 * passed in registers will be done at a later stage.
	 */
	for (size_t i = 0; i < args.size() && i <= 5; i++) {
		formals_.push_back(alloc_local(args[i]));
	}
	for (size_t i = 6; i < args.size(); i++) {
		formals_.push_back(new in_frame((i - 6) * 8 + 16));
	}
}

utils::ref<access> frame::alloc_local(bool escapes)
{
	if (escapes)
		return new in_frame(-(escaping_count_++ * 8 + 8));
	reg_count_++;
	return new in_reg(temp::temp());
}

backend::tree::rstm frame::proc_entry_exit_1(backend::tree::rstm s,
					     ::temp::label ret_lbl)
{
	// Placeholder for the epilogue
	return new backend::tree::seq({s, new backend::tree::label(ret_lbl)});
}
} // namespace frame
