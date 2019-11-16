%expect 0
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
	FUN "FUN"
	EOF 0 "eof"

%token <symbol> ID "id"
%token <int> INT "int"

%type <exp*> program;
%type <exp*> exp;
%type <seq*> exps;
%type <seq*> exps_body;
%type <binop> binop;
%type <exp*> lvalue;
%type <fun*> fun;
%type <seq*> decs;
%type <seq*> decs_body;
%type <std::vector<id*>> id_list;
%type <std::vector<id*>> id_list_body;
%type <id*> id;

%%

%start program;

program: decs EOF 		{ d.prog_ = $1; };

decs: LPAREN decs_body RPAREN 	{ $$ = $2; };

decs_body:
	 %empty 		{ $$ = new seq(); }
| 	 decs_body fun 		{ $$ = $1; $1->children_.push_back($2); };

fun: FUN ID id_list exps  	{ $$ = new fun(new id($2), $3, $4); };

exps: LPAREN exps_body RPAREN 	{ $$ = $2; };

exps_body:
	%empty 			{ $$ = new seq(); }
| 	exps_body exp 		{ $$ = $1; $1->children_.push_back($2); };

exp:
	INT 				{ $$ = new num($1); }
| 	ID 				{ $$ = new id($1); }
| 	ASSIGN lvalue exp 		{ $$ = new bin(binop::ASSIGN, $2, $3); }
| 	binop exp exp 			{ $$ = new bin($1, $2, $3); }
| 	exps 				{ $$ = $1; };

binop:
 	EQ 			{ $$ = binop::EQ; }
| 	MINUS 			{ $$ = binop::MINUS; }
| 	PLUS 			{ $$ = binop::PLUS; }
| 	MULT 			{ $$ = binop::MULT; }
| 	DIV 			{ $$ = binop::DIV; };

id: ID 				{ $$ = new id($1); };
id_list:
	LPAREN id_list_body RPAREN	{ $$ = $2; };

id_list_body:
	%empty 				{ $$ = std::vector<id*>(); }
| 	id_list_body id 		{ $$ = $1; $1.push_back($2); };

lvalue: id 		{ $$ = $1; };
%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
