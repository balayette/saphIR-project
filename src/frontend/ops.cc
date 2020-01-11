#include "frontend/ops.hh"

namespace ops
{
const std::string binop_str[] = {"-", "+", "*", "/", "%"};
const std::string cmpop_str[] = {"==", "!="};

cmpop invert_cmpop(cmpop op)
{
	if (op == cmpop::EQ)
		return cmpop::NEQ;
	return cmpop::EQ;
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
