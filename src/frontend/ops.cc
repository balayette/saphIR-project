#include "frontend/ops.hh"

namespace ops
{
const std::string binop_str[] = {
	"-", "+", "*", "/", "%", "&&", "||", "&", "|", "^", "<<", ">>", "|>>"
};

const std::string cmpop_str[] = {
	"==", "<", ">", "<=", ">=", "!=",
};

cmpop invert_cmpop(cmpop op)
{
	auto mid = static_cast<unsigned>(cmpop::NEQ) / 2;
	auto idx = static_cast<unsigned>(op);
	if (idx > mid)
		return static_cast<cmpop>(mid + 1 - (idx - mid));
	else
		return static_cast<cmpop>(static_cast<unsigned>(cmpop::NEQ)
					  - idx);
}

bool is_binop_commutative(binop op)
{
	return op == binop::MULT || op == binop::PLUS || op == binop::AND
	       || op == binop::OR || op == binop::BITOR || op == binop::BITAND
	       || op == binop::BITXOR;
}

const std::string &binop_to_string(binop op)
{
	return binop_str[static_cast<int>(op)];
}

const std::string &cmpop_to_string(cmpop op)
{
	return cmpop_str[static_cast<int>(op)];
}
} // namespace ops
