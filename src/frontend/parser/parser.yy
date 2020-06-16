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
        #include "utils/ref.hh"
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
        NOT "!"
	AMPERSAND "&"
	BITOR "|"
        BITXOR "^"
        BITRSHIFT ">>"
        ARITHBITRSHIFT "|>>"
        BITLSHIFT "<<"
        AND "&&"
	OR "||"
	LPAREN "("
	RPAREN ")"
	LBRACE "{"
	RBRACE "}"
        LBRACK "["
        RBRACK "]"
	SEMI ";"
	COLON ","
        DOT "."
        ARROW "->"
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

%type <utils::ref<decs>> decs

%type <utils::ref<fundec>> fundec
%type <utils::ref<funprotodec>> funprotodec

%type <std::vector<utils::ref<memberdec>>> memberdecs
%type <std::vector<utils::ref<memberdec>>> memberdecsp
%type <utils::ref<memberdec>> memberdec

%type <utils::ref<structdec>> structdec

%type <std::vector<utils::ref<locdec>>> argdecs
%type <std::vector<utils::ref<locdec>>> argdecsp
%type <utils::ref<locdec>> argdec

%type <std::vector<utils::ref<stmt>>> stmts
%type <std::vector<utils::ref<stmt>>> stmtsp
%type <utils::ref<stmt>> stmt
%type <utils::ref<stmt>> stmt_body

%type <utils::ref<braceinit>> braceinit
%type <utils::ref<locdec>> locdec
%type <utils::ref<globaldec>> globaldec
%type <utils::ref<sexp>> sexp
%type <utils::ref<ret>> ret
%type <utils::ref<ifstmt>> ifstmt
%type <utils::ref<forstmt>> forstmt

%type <utils::ref<exp>> exp
%type <std::vector<utils::ref<exp>>> exps_comma
%type <std::vector<utils::ref<exp>>> exps_commap

%type <utils::ref<ass>> ass
%type <utils::ref<num>> num
%type <utils::ref<ref>> ref
%type <utils::ref<call>> call
%type <utils::ref<exp>> memberaccess
%type <utils::ref<subscript>> subscript

%type <utils::ref<types::ty>> type

%left OR
%left AND

%left BITNOT
%left BITAND // &, but used for precendance
%left BITOR
%left BITXOR

%nonassoc ASSIGN
%nonassoc SMLR GRTR SMLR_EQ GRTR_EQ
%nonassoc EQ NEQ

%left BITLSHIFT BITRSHIFT ARITHBITRSHIFT

%left PLUS MINUS
%left MULT DIV MOD

%left AMPERSAND
%left DOT ARROW LBRACK RBRACK
%right NOT

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
          %empty        { $$ = std::vector<utils::ref<memberdec>>(); }
|         memberdecsp 
;

memberdecsp:
           memberdec   { $$ = std::vector<utils::ref<memberdec>>(); $$.push_back($1); }
|          memberdecsp "," memberdec { $1.push_back($3); $$ = $1; }
;

memberdec: type ID { $$ = new memberdec($1, $2); };

braceinit: "{" exps_comma "}" { $$ = new braceinit($2); };

argdecs:
       	%empty 			{ $$ = std::vector<utils::ref<locdec>>(); }
| 	argdecsp
;

argdecsp:
	argdec 			{ $$ = std::vector<utils::ref<locdec>>(); $$.push_back($1); }
| 	argdecsp "," argdec	{ $1.push_back($3); $$ = $1; }
;

argdec: type ID 	{ $$ = new locdec($1, $2, nullptr); };

stmts:
     	%empty 		{ $$ = std::vector<utils::ref<stmt>>(); }
| 	stmtsp
;

stmtsp:
      	stmt 		{ $$ = std::vector<utils::ref<stmt>>(); $$.push_back($1); }
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

locdec:
      "let" type ID "=" exp { $$ = new locdec($2, $3, $5); }
;
globaldec:
         "let" type ID "=" exp { $$ = new globaldec($2, $3, $5); }
;

/* TODO: This accepts 1; */
sexp: exp { $$ = new sexp($1); };

ret:
	"return" 	{ $$ = new ret(nullptr); }   
| 	"return" exp 	{ $$ = new ret($2); }
;

ifstmt:
      	IF "(" exp ")" stmts FI { 
		$$ = new ifstmt($3, $5, std::vector<utils::ref<stmt>>()); 
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
|       "(" exp ")"             { $$ = new paren($2); }
|	num 			{ $$ = $1; }
| 	call 			{ $$ = $1; }
|       braceinit               { $$ = $1; }
|       memberaccess            { $$ = $1; }
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

|       exp AMPERSAND exp      %prec BITAND { $$ = new bin(binop::BITAND, $1, $3); }
| 	exp BITOR exp 		{ $$ = new bin(binop::BITOR, $1, $3); }
| 	exp BITXOR exp 		{ $$ = new bin(binop::BITXOR, $1, $3); }
| 	exp BITLSHIFT exp 		{ $$ = new bin(binop::BITLSHIFT, $1, $3); }
| 	exp BITRSHIFT exp 		{ $$ = new bin(binop::BITRSHIFT, $1, $3); }
| 	exp ARITHBITRSHIFT exp 		{ $$ = new bin(binop::ARITHBITRSHIFT, $1, $3); }

|       NOT exp { $$ = new unary(unaryop::NOT, $2); }
| 	exp OR exp 		{ $$ = new bin(binop::OR, $1, $3); }
| 	exp AND exp 		{ $$ = new bin(binop::AND, $1, $3); }
|       subscript { $$ = $1; }
;

subscript: exp "[" exp "]" { $$ = new subscript($1, $3); }

exps_comma:
	%empty 			{ $$ = std::vector<utils::ref<exp>>(); }
| 	exps_commap		{ $$ = $1; }
;

exps_commap:
	exp 			{ $$ = std::vector<utils::ref<exp>>(); $$.push_back($1); }
| 	exps_commap "," exp 	{ $1.push_back($3); $$ = $1; }
;

ass: exp "=" exp 		{ $$ = new ass($1, $3); };

num: INT_LIT 	{ $$ = new num($1); };

ref: ID 	{ $$ = new ref($1); };

call: ID "(" exps_comma ")" 	{ $$ = new call($1, $3); };

memberaccess:
            exp "." ID { $$ = new memberaccess($1, $3); }
|           exp "->" ID { $$ = new arrowaccess($1, $3); }
;

type:
	ID { $$ = new types::named_ty($1); }
|       ID "<" INT_LIT ">" { $$ = new types::named_ty($1, $3); }
| 	type "*" { $$ = new types::pointer_ty($1); }
|       type "[" INT_LIT "]" { $$ = new types::array_ty($1, $3); }
;

%%

void yy::parser::error (const location_type& l, const std::string& m)
{
	std::cerr << l << ":" << m << '\n';
}
