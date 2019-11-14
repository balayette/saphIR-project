#include "symbol.hh"

symbol::symbol(const std::string &str)
{
	get_set().insert(str);
	instance_ = &(*(get_set().find(str)));
}

symbol::symbol(const char *str) : symbol(std::string(str)) {}

std::set<std::string> &symbol::get_set()
{
	static std::set<std::string> set{};

	return set;
}

symbol &symbol::operator=(const symbol &rhs)
{
	if (this == &rhs)
		return *this;

	instance_ = rhs.instance_;
	return *this;
}

bool symbol::operator==(const symbol &rhs) const
{
	return rhs.instance_ == instance_;
}

bool symbol::operator!=(const symbol &rhs) const
{
	return !(rhs.instance_ == instance_);
}

std::ostream &operator<<(std::ostream &ostr, const symbol &the)
{
	return ostr << *the.instance_;
}

size_t symbol::size() const { return instance_->size(); }

const std::string &symbol::get() const { return *instance_; }
