#pragma once

#include <ostream>
#include <string>

class Token {
public:
  enum TokenType { ATOM, LPAREN, RPAREN };

  Token(TokenType type, int line, int pos);

  void SetString(const std::string &str);
  std::string &GetString();

  TokenType GetType();

  int GetLine();
  int GetPos();

  friend std::ostream &operator<<(std::ostream &stream, const Token &tok);

private:
  std::string str_;
  TokenType type_;
  int line_;
  int pos_;
};
