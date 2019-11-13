#include "lexer.hh"

#include <iostream>
#include <string>

#define MAKE_TOK(Type) std::make_shared<Token>(Type, line_, pos_);

Lexer::Lexer(std::istream &stream)
    : stream_(stream), state_(START), rollback_(false), pos_(0), line_(1),
      filename_("stdin") {
  Eat();
}

Lexer::Lexer(std::istream &stream, const std::string &filename)
    : stream_(stream), state_(START), rollback_(false), pos_(0), line_(1),
      filename_(filename) {
  Eat();
}

const std::string &Lexer::get_filename() const { return filename_; }

char Lexer::nextChar() {
  char c = 0;
  stream_.get(c);
  last_char_ = c;
  if (c == '\n') {
    line_++;
    pos_ = 0;
  } else
    pos_++;

  return c;
}

std::shared_ptr<Token> Lexer::Peek() {
  if (stream_.eof())
    return nullptr;
  return tok_;
}

void Lexer::Eat() {
  if (stream_.eof())
    tok_ = nullptr;

  char c = 0;
  while (!stream_.eof()) {
    if (rollback_) {
      rollback_ = false;
      c = last_char_;
    } else {
      c = nextChar();
    }

    switch (state_) {
    case START:
      handleStart(c);
      break;
    case ATOM:
      handleAtom(c);
      break;
    case STRING_LIT:
      handleStringLit(c);
      break;
    }
    if (state_ == START)
      break;
  }
}

void Lexer::handleStart(char c) {
  switch (c) {
  case '(':
    state_ = START;
    tok_ = MAKE_TOK(Token::LPAREN);
    break;
  case ')':
    state_ = START;
    tok_ = MAKE_TOK(Token::RPAREN);
    break;
  case '"':
    state_ = STRING_LIT;
    tok_ = MAKE_TOK(Token::ATOM);
    tok_->SetString(std::string("\""));
    break;
  case ' ':
  case '\t':
  case '\n':
    handleStart(nextChar());
    break;
  case EOF:
    state_ = START;
    return;
  default:
    state_ = ATOM;
    tok_ = MAKE_TOK(Token::ATOM);
    tok_->SetString(std::string(""));
    rollback_ = true;
    break;
  }
}

void Lexer::handleAtom(char c) {
  switch (c) {
  case ' ':
  case '(':
  case ')':
  case '"':
  case '\n':
    state_ = START;
    if (c == '(' || c == ')' || c == '"') {
      rollback_ = true;
      last_char_ = c;
    }
    return;
  default:
    tok_->GetString().append(1, c);
    break;
  }
}

void Lexer::handleStringLit(char c) {
  switch (c) {
  case '"':
    state_ = START;
    tok_->GetString().append(1, c);
    return;
  case '\\':
    c = nextChar();
    if (c == EOF) {
      std::cerr << "Unexpected EOF at line " << line_ << " char " << pos_
                << '\n';
      std::exit(1);
    }
    if (c != '"')
      tok_->GetString().append(1, '\\');
    tok_->GetString().append(1, c);
    break;
  default:
    tok_->GetString().append(1, c);
    break;
  }
}
