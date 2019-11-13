#pragma once

#include <istream>
#include <memory>
#include <variant>

#include "token.hh"

class Lexer {
public:
  explicit Lexer(std::istream &stream);
  explicit Lexer(std::istream &stream, const std::string &filename);

  std::shared_ptr<Token> Peek();
  void Eat();

  const std::string &get_filename() const;

private:
  enum States { START, ATOM, STRING_LIT };

  void handleStart(char c);
  void handleAtom(char c);
  void handleStringLit(char c);

  char nextChar();

  std::shared_ptr<Token> tok_;
  std::istream &stream_;
  States state_;

  char last_char_;
  bool rollback_;

  int pos_;
  int line_;

  std::string filename_;
};
