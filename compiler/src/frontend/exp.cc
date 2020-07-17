#include "frontend/exp.hh"
#include "mach/target.hh"

namespace frontend
{
exp::exp() : ty_(nullptr) {}
num::num(uint64_t value) : exp(), value_(value) {}
str_lit::str_lit(const std::string &str) : exp(), str_(str) {}
cmp::cmp(ops::cmpop op, utils::ref<exp> lhs, utils::ref<exp> rhs)
    : exp(), op_(op), lhs_(lhs), rhs_(rhs)
{
}
} // namespace frontend
