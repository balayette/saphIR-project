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
	SMLR "<"
	GRTR ">"
	SMLR_EQ "<="
	GRTR_EQ ">="
	NEQ "!="
	MINUS "-"
	PLUS "+"
	MOD "%"
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
        LET "let"
        VARIADIC "variadic"
        STRUCT "struct"
	EOF 0 "eof"

%token <symbol> ID "id"
%token <int> INT_LIT "int_lit"
%token <std::string> STR_LIT "str_lit"

%type <decs*> decs

%type <fundec*> fundec
%type <funprotodec*> funprotodec

%type <std::vector<memberdec*>> memberdecs
%type <std::vector<memberdec*>> memberdecsp
%type <memberdec*> memberdec

%type <structdec*> structdec

%type <std::vector<locdec*>> argdecs
%type <std::vector<locdec*>> argdecsp
%type <locdec*> argdec

%type <std::vector<stmt*>> stmts
%type <std::vector<stmt*>> stmtsp
%type <stmt*> stmt
%type <stmt*> stmt_body

%type <braceinit*> braceinit
%type <locdec*> locdec
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

%type <types::ty*> type

%nonassoc EQ NEQ SMLR GRTR SMLR_EQ GRTR_EQ ASSIGN
%left AMPERSAND
%left PLUS MINUS MOD
%left MULT DIV

%%

start: program

program: decs 	{ d.prog_ = $1; };

decs:
	%empty          { $$ = new decs(); }
|   	decs fundec     { $$ = $1; $1->decs_.push_back($2); }
| 	decs globaldec ";"      { $$ = $1; $1->decs_.push_back($2); }
|       decs funprotodec ";" { $$ = $1; $1->decs_.push_back($2); }
|       decs structdec ";" { $$ = $1; $1->decs_.push_back($2); }
;

funprotodec: 
        "fun" ID "(" argdecs ")" type { $$ = new funprotodec($6, $2, $4); }
|       "fun" ID "(" argdecs ")" type "variadic" { $$ = new funprotodec($6, $2, $4, true); }
;

fundec: "fun" ID "(" argdecs ")" type "{" stmts "}" {
      $$ = new fundec($6, $2, $4, $8);
};

structdec: "struct" ID "{" memberdecs "}" { $$ = new structdec($2, $4); };

memberdecs:
          %empty        { $$ = std::vector<memberdec*>(); }
|         memberdecsp 
;

memberdecsp:
           memberdec   { $$ = std::vector<memberdec*>(); $$.push_back($1); }
|          memberdecsp "," memberdec { $1.push_back($3); $$ = $1; }
;

memberdec: type ID { $$ = new memberdec($1, $2); };

braceinit: "{" exps_comma "}" { $$ = new braceinit($2); };

argdecs:
       	%empty 			{ $$ = std::vector<locdec*>(); }
| 	argdecsp
;

argdecsp:
	argdec 			{ $$ = std::vector<locdec*>(); $$.push_back($1); }
| 	argdecsp "," argdec	{ $1.push_back($3); $$ = $1; }
;

argdec: type ID 	{ $$ = new locdec($1, $2, nullptr); };

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
	locdec 	{ $$ = $1; }
| 	sexp 	{ $$ = $1; }
| 	ret 	{ $$ = $1; }
| 	ass 	{ $$ = $1; }
;

locdec: "let" type ID "=" exp { $$ = new locdec($2, $3, $5); };
globaldec: "let" type ID "=" exp { $$ = new globaldec($2, $3, $5); };

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
|       braceinit               { $$ = $1; }
| 	AMPERSAND exp           { $$ = new addrof($2); }
| 	STR_LIT 		{ $$ = new str_lit($1); }
| 	exp EQ exp 		{ $$ = new cmp(cmpop::EQ, $1, $3); }
| 	exp NEQ exp 		{ $$ = new cmp(cmpop::NEQ, $1, $3); }
|	exp SMLR exp	{$$ = new cmp(cmpop::SMLR, $1, $3); }
|	exp GRTR exp	{$$ = new cmp(cmpop::GRTR, $1, $3); }
|	exp SMLR_EQ exp	{$$ = new cmp(cmpop::SMLR_EQ, $1, $3); }
|	exp GRTR_EQ exp	{$$ = new cmp(cmpop::GRTR_EQ, $1, $3); }
| 	exp MULT exp 		{ $$ = new bin(binop::MULT, $1, $3); }
| 	exp DIV exp 		{ $$ = new bin(binop::DIV, $1, $3); }
| 	exp MOD exp 		{ $$ = new bin(binop::MOD, $1, $3); }
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
	ID { $$ = new types::named_ty($1); }
| 	type "*" { $$ = $1; $$->ptr_++; }
;

%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
