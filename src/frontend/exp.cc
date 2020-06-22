#include "frontend/exp.hh"
#include "mach/target.hh"

namespace frontend
{
exp::exp() : ty_(mach::TARGET().invalid_type()) {}
num::num(int64_t value) : exp(mach::TARGET().integer_type()), value_(value) {}
str_lit::str_lit(const std::string &str)
    : exp(mach::TARGET().string_type()), str_(str)
{
}
cmp::cmp(ops::cmpop op, utils::ref<exp> lhs, utils::ref<exp> rhs)
    : exp(mach::TARGET().integer_type()), op_(op), lhs_(lhs), rhs_(rhs)
{
}
} // namespace frontend
