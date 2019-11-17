#include "exp.hh"

const std::string binop_str[] = {"-", "+", "*", "/"};
const std::string cmpop_str[] = {"==", "!="};

const std::string &binop_to_string(binop op)
{
	return binop_str[static_cast<int>(op)];
}

const std::string &cmpop_to_string(cmpop op)
{
	return cmpop_str[static_cast<int>(op)];
}
