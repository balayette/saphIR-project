#pragma once

#include <string>

namespace ops
{
enum class binop { MINUS, PLUS, MULT, DIV };
enum class cmpop { EQ, NEQ };

const std::string &binop_to_string(binop op);
const std::string &cmpop_to_string(cmpop op);
} // namespace ops
