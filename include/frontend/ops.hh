#pragma once

#include <string>

namespace ops
{
enum class binop {
	MINUS,
	PLUS,
	MULT,
	DIV,
	MOD,
	AND,
	OR,
	BITAND,
	BITOR,
	BITXOR,
	BITLSHIFT,
	BITRSHIFT,
	ARITHBITRSHIFT,
};

// The order of the cmpops matters, they must be ordered "symmetrically".
// See invert_cmpop
enum class cmpop { EQ, SMLR, GRTR, SMLR_EQ, GRTR_EQ, NEQ };

cmpop invert_cmpop(cmpop op);

bool is_binop_commutative(binop op);

const std::string &binop_to_string(binop op);
const std::string &cmpop_to_string(cmpop op);
} // namespace ops
