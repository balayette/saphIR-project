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
	#include "stmt.hh"
	#include "exp.hh"
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
	NEQ "!="
	MINUS "-"
	PLUS "+"
	MULT "*"
	DIV "/"
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

%type <std::vector<argdec*>> argdecs
%type <argdec*> argdec

%type <std::vector<stmt*>> stmts
%type <stmt*> stmt
%type <stmt*> stmt_body

%type <vardec*> vardec
%type <sexp*> sexp
%type <ret*> ret
%type <ifstmt*> ifstmt
%type <forstmt*> forstmt

%type <exp*> exp
%type <std::vector<exp*>> exps_comma

%type <ass*> ass
%type <num*> num
%type <ref*> ref
%type <call*> call

%type <ty> type

%nonassoc EQ NEQ ASSIGN
%left PLUS MINUS
%left MULT DIV

%%

start: program

program: decs 	{ d.prog_ = $1; };

decs:
	%empty 		{ $$ = new decs(); }
|   	decs fundec 	{ $$ = $1; $1->fundecs_.push_back($2); }
| 	decs vardec ";" { $$ = $1; $1->vardecs_.push_back($2); }
;

fundec: "fun" ID "(" argdecs ")" type "{" stmts "}" { 
      $$ = new fundec($6, $2, $4, $8); 
};

argdecs:
       	%empty 			{ $$ = std::vector<argdec*>(); }
| 	argdecs "," argdec 	{ $$ = $1; $1.push_back($3); }
;

argdec: type ID 	{ $$ = new argdec($1, $2); };

stmts:
     	%empty 		{ $$ = std::vector<stmt*>(); }
| 	stmts stmt 	{ $$ = $1; $1.push_back($2); }
;

stmt: stmt_body ";" 	{ $$ = $1; };

stmt_body: 
	vardec 	{ $$ = $1; }
| 	sexp 	{ $$ = $1; }
| 	ret 	{ $$ = $1; }
| 	ifstmt  { $$ = $1; }
| 	forstmt { $$ = $1; }
;

vardec: type ID "=" exp { $$ = new vardec($1, $2, $4); };

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

forstmt: FOR "(" stmt ";" exp ";" stmt ")" stmts ROF {
		$$ = new forstmt($3, $5, $7, $9);
       };

exp:
 	ass 		{ $$ = $1; }
| 	num 		{ $$ = $1; }
| 	ref 		{ $$ = $1; }
| 	call 		{ $$ = $1; }
| 	exp EQ exp 	{ $$ = new cmp(cmpop::EQ, $1, $3); }
| 	exp NEQ exp 	{ $$ = new cmp(cmpop::NEQ, $1, $3); }
| 	exp MULT exp 	{ $$ = new bin(binop::MULT, $1, $3); }
| 	exp DIV exp 	{ $$ = new bin(binop::DIV, $1, $3); }
| 	exp PLUS exp 	{ $$ = new bin(binop::PLUS, $1, $3); }
| 	exp MINUS exp 	{ $$ = new bin(binop::MINUS, $1, $3); }
;

exps_comma:
	%empty 			{ $$ = std::vector<exp*>(); }
| 	exps_comma "," exp 	{ $$ = $1; $1.push_back($3); }
;

ass: ID "=" exp 	{ $$ = new ass($1, $3); };

num: INT_LIT 	{ $$ = new num($1); };

ref: ID 	{ $$ = new ref($1); };

call: ID "(" exps_comma ")" 	{ $$ = new call($1, $3); };

type:
    	INT 	{ $$ = ty::INT; }
| 	STRING 	{ $$ = ty::STRING; }
| 	VOID 	{ $$ = ty::VOID; }
;

%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
