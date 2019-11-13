#pragma once

#include <memory>

#include "token.hh"

class Tree {
       public:
	Tree() = default;
	Tree(std::shared_ptr<Token> tok);

       private:
	const std::shared_ptr<Token> tok_;
}

