#include "parser.hh"
#include "pool.hh"

#include <iostream>
#include <stack>

#include "token.hh"

Parser::Parser(Lexer &lexer) : lexer_(lexer) {}

Tree *Parser::Parse() {
  auto stack = std::stack<Tree *>{};

  stack.push(new Tree());

  for (auto tok = lexer_.Peek(); tok != nullptr;
       lexer_.Eat(), tok = lexer_.Peek()) {
    auto type = tok->GetType();
    if (type == Token::TokenType::LPAREN)
      stack.push(new Tree());
    else if (type == Token::TokenType::RPAREN) {
      auto top = stack.top();
      stack.pop();
      if (stack.size() == 0) {
        std::cerr << "Unexpected ) at " << lexer_.get_filename() << ':'
                  << tok->GetLine() << ':' << tok->GetPos() << '\n';
        std::exit(2);
      }

      auto t = stack.top();
      t->AddChild(top);
    } else {
      if (stack.top()->GetValue().size() == 0) {
        delete stack.top();
        stack.pop();
        stack.push(new Tree(tok->GetString()));
      } else {
        auto add = new Tree(tok->GetString());
        stack.top()->AddChild(add);
      }
    }
  }

  auto ret = stack.top();

  while (ret->GetValue().size() == 0) {
    auto tmp = ret;
    ret = ret->GetChildren()[0];
    delete tmp;
  }

  pool::AddTree(ret);

  return ret;
}
