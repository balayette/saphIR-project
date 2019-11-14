%skeleton "lalr1.cc"
%require "3.4"
%defines

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%code requires {
	#include <string>
	#include "symbol.hh"
	class driver;
}

%param { driver& d }

%locations

%define parse.error verbose

%code {
	#include "driver.hh"
}

%define api.token.prefix {TOK_}

%token  ASSIGN "="
	EQ "=="
	MINUS "-"
	PLUS "+"
	MULT "*"
	DIV "/"
	LPAREN "("
	RPAREN ")"
	EOF 0 "eof"

%token <symbol> ID "id"
%token <int> INT "int"

%printer { yyo << $$; } <*>;

%%

%start program;

program: exps EOF;

exps:
	%empty
| 	exps exp;

exp: 	"(" exp_body ")";

exp_body:
	INT
| 	ID
| 	binop lvalue exp;

binop:
	ASSIGN
| 	EQ
| 	MINUS
| 	PLUS
| 	MULT
| 	DIV;

lvalue: ID;
%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
