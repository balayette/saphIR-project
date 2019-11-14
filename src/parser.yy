%skeleton "lalr1.cc"
%require "3.4"
%defines

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%code requires {
	#include <string>
	#include "symbol.hh"
	#include "ast.hh"
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

%type <exp*> program;
%type <seq*> exps;
%type <exp*> exp;
%type <binop> binop;
%type <exp*> lvalue;

%%

%start program;

program: exps EOF 		{ d.prog_ = $1; };

exps:
	%empty 			{ $$ = new seq(); }
| 	exps exp 		{ $$ = $1; $1->children_.push_back($2); };

exp:
	INT 				{ $$ = new num($1); }
| 	ID 				{ $$ = new id($1); }
| 	LPAREN ASSIGN lvalue exp RPAREN	{ $$ = new bin(binop::ASSIGN, $3, $4); }
| 	LPAREN binop exp exp RPAREN 	{ $$ = new bin($2, $3, $4); }
| 	LPAREN exp RPAREN 		{ $$ = $2; };

binop:
 	EQ 			{ $$ = binop::EQ; }
| 	MINUS 			{ $$ = binop::MINUS; }
| 	PLUS 			{ $$ = binop::PLUS; }
| 	MULT 			{ $$ = binop::MULT; }
| 	DIV 			{ $$ = binop::DIV; };

lvalue: ID 			{ $$ = new id($1); };
%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
