#pragma once

#include <memory>

#include "lexer.hh"
#include "token.hh"
#include "tree.hh"

class Parser {
public:
  Parser(Lexer &lexer);

  Tree *Parse();

private:
  Lexer &lexer_;
};
