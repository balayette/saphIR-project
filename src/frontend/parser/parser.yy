%expect 0
%skeleton "lalr1.cc"
%require "3.4"
%defines

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%code requires {
	#include <string>
	#include "utils/symbol.hh"
	#include "frontend/stmt.hh"
	#include "frontend/exp.hh"
	class driver;

	using namespace frontend;
        using namespace ops;
}

%param { driver& d }

%locations

%define parse.error verbose

%code {
	#include "driver/driver.hh"
}

%define api.token.prefix {TOK_}

%token  ASSIGN "="
	EQ "=="
	NEQ "!="
	MINUS "-"
	PLUS "+"
	MULT "*"
	DIV "/"
	AMPERSAND "&"
	LPAREN "("
	RPAREN ")"
	LBRACE "{"
	RBRACE "}"
	SEMI ";"
	COLON ","
	FUN "fun"
	FOR "for"
	ROF "rof"
	IF "if"
	ELSE "else"
	FI "fi"
	RETURN "return"
	INT "int"
	VOID "void"
	STRING "string"
	EOF 0 "eof"

%token <symbol> ID "id"
%token <int> INT_LIT "int_lit"
%token <std::string> STR_LIT "str_lit"

%type <decs*> decs

%type <fundec*> fundec
%type <funprotodec*> funprotodec

%type <std::vector<vardec*>> argdecs
%type <std::vector<vardec*>> argdecsp
%type <vardec*> argdec

%type <std::vector<stmt*>> stmts
%type <std::vector<stmt*>> stmtsp
%type <stmt*> stmt
%type <stmt*> stmt_body

%type <vardec*> vardec
%type <globaldec*> globaldec
%type <sexp*> sexp
%type <ret*> ret
%type <ifstmt*> ifstmt
%type <forstmt*> forstmt

%type <exp*> exp
%type <std::vector<exp*>> exps_comma
%type <std::vector<exp*>> exps_commap

%type <ass*> ass
%type <num*> num
%type <ref*> ref
%type <call*> call

%type <types::ty> type

%nonassoc EQ NEQ ASSIGN
%left AMPERSAND
%left PLUS MINUS
%left MULT DIV

%%

start: program

program: decs 	{ d.prog_ = $1; };

decs:
	%empty          { $$ = new decs(); }
|   	decs fundec     { $$ = $1; $1->fundecs_.push_back($2); }
| 	decs globaldec ";"      { $$ = $1; $1->vardecs_.push_back($2); }
|       decs funprotodec ";" { $$ = $1; $1->funprotodecs_.push_back($2); }
;

funprotodec: "fun" ID "(" argdecs ")" type {
      $$ = new funprotodec($6, $2, $4);
};

fundec: "fun" ID "(" argdecs ")" type "{" stmts "}" {
      $$ = new fundec($6, $2, $4, $8);
};

argdecs:
       	%empty 			{ $$ = std::vector<vardec*>(); }
| 	argdecsp
;

argdecsp:
	argdec 			{ $$ = std::vector<vardec*>(); $$.push_back($1); }
| 	argdecsp "," argdec	{ $1.push_back($3); $$ = $1; }
;

argdec: type ID 	{ $$ = new vardec($1, $2, nullptr); };

stmts:
     	%empty 		{ $$ = std::vector<stmt*>(); }
| 	stmtsp
;

stmtsp:
      	stmt 		{ $$ = std::vector<stmt*>(); $$.push_back($1); }
| 	stmtsp stmt 	{ $1.push_back($2); $$ = $1; }
;

stmt: 
    	stmt_body SEMI 	{ $$ = $1; }
| 	ifstmt  { $$ = $1; }
| 	forstmt { $$ = $1; }
;

stmt_body: 
	vardec 	{ $$ = $1; }
| 	sexp 	{ $$ = $1; }
| 	ret 	{ $$ = $1; }
| 	ass 	{ $$ = $1; }
;

vardec: type ID "=" exp { $$ = new vardec($1, $2, $4); };
globaldec: type ID "=" exp { $$ = new globaldec($1, $2, $4); };

/* TODO: This accepts 1; */
sexp: exp { $$ = new sexp($1); };

ret:
	"return" 	{ $$ = new ret(nullptr); }   
| 	"return" exp 	{ $$ = new ret($2); }
;

ifstmt:
      	IF "(" exp ")" stmts FI { 
		$$ = new ifstmt($3, $5, std::vector<stmt*>()); 
	}
| 	IF "(" exp ")" stmts ELSE stmts FI {
		$$ = new ifstmt($3, $5, $7);
	}
;

forstmt:
	FOR "(" stmt_body SEMI exp SEMI exp ")" stmts ROF {
		$$ = new forstmt($3, $5, new sexp($7), $9);
	}
	/*
	Assignment is a statement, but is allowed here...
	return statements are not allowed, though.
	*/
| 	FOR "(" stmt_body SEMI exp SEMI ass ")" stmts ROF {
		$$ = new forstmt($3, $5, $7, $9);
	}
;

exp:
 	ref 			{ $$ = $1; }
| 	MULT exp 		{ $$ = new deref($2); }
|	num 			{ $$ = $1; }
| 	call 			{ $$ = $1; }
| 	AMPERSAND exp           { $$ = new addrof($2); }
| 	STR_LIT 		{ $$ = new str_lit($1); }
| 	exp EQ exp 		{ $$ = new cmp(cmpop::EQ, $1, $3); }
| 	exp NEQ exp 		{ $$ = new cmp(cmpop::NEQ, $1, $3); }
| 	exp MULT exp 		{ $$ = new bin(binop::MULT, $1, $3); }
| 	exp DIV exp 		{ $$ = new bin(binop::DIV, $1, $3); }
| 	exp PLUS exp 		{ $$ = new bin(binop::PLUS, $1, $3); }
| 	exp MINUS exp 		{ $$ = new bin(binop::MINUS, $1, $3); }
;

exps_comma:
	%empty 			{ $$ = std::vector<exp*>(); }
| 	exps_commap		{ $$ = $1; }
;

exps_commap:
	exp 			{ $$ = std::vector<exp*>(); $$.push_back($1); }
| 	exps_commap "," exp 	{ $1.push_back($3); $$ = $1; }
;

ass: exp "=" exp 		{ $$ = new ass($1, $3); };

num: INT_LIT 	{ $$ = new num($1); };

ref: ID 	{ $$ = new ref($1); };

call: ID "(" exps_comma ")" 	{ $$ = new call($1, $3); };

type:
    	INT	{ $$ = types::type::INT; }
| 	STRING 	{ $$ = types::type::STRING; }
| 	VOID 	{ $$ = types::type::VOID; }
| 	type MULT { $$ = $1; $$.ptr_++; }
;

%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
