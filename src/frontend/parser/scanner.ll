%{
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>

#include "driver/driver.hh"
#include "frontend/parser/parser.hh"
#include "utils/assert.hh"
%}

%option noyywrap nounput noinput batch debug

%{
#define TOKEN_VAL(Type, Value) yy::parser::make_##Type(Value, d.location_)

#define TOKEN(Type) yy::parser::make_##Type(d.location_)

#define yyterminate() return TOKEN(EOF)
%}

id 	[a-zA-Z][a-zA-Z_0-9]*
int 	-?[0-9]+
hexint 	0x-?[0-9A-Fa-f]+
blank 	[ \t\r]
strlit \"[^"]*\"

%%

{blank}+ 	d.location_.step();
\n+ 	 	{ d.location_.lines(yyleng); d.location_.step(); }

"=" 		return TOKEN(ASSIGN);
"==" 		return TOKEN(EQ);
"<" 		return TOKEN(SMLR);
">" 		return TOKEN(GRTR);
"<=" 		return TOKEN(SMLR_EQ);
">=" 		return TOKEN(GRTR_EQ);
"!=" 		return TOKEN(NEQ);
"-"	    	return TOKEN(MINUS);
"+"	    	return TOKEN(PLUS);
"*"	    	return TOKEN(MULT);
"/"	    	return TOKEN(DIV);
"%"	    	return TOKEN(MOD);
"&" 		return TOKEN(AMPERSAND);
"!"             return TOKEN(NOT);
"~"             return TOKEN(TILDE);

"|"            return TOKEN(BITOR);
"^"            return TOKEN(BITXOR);
">>"           return TOKEN(BITRSHIFT);
"|>>"           return TOKEN(ARITHBITRSHIFT);
"<<"           return TOKEN(BITLSHIFT);

"&&"            return TOKEN(AND);
"||"            return TOKEN(OR);
"("	    	return TOKEN(LPAREN);
")"	    	return TOKEN(RPAREN);
"{"	    	return TOKEN(LBRACE);
"}"	    	return TOKEN(RBRACE);
";"	    	return TOKEN(SEMI);
","	    	return TOKEN(COMMA);
"."             return TOKEN(DOT);
"->"            return TOKEN(ARROW);
"["             return TOKEN(LBRACK);
"]"             return TOKEN(RBRACK);
"fun" 		return TOKEN(FUN);
"for"	    	return TOKEN(FOR);
"rof"	    	return TOKEN(ROF);
"if"	    	return TOKEN(IF);
"else"	    	return TOKEN(ELSE);
"fi"	    	return TOKEN(FI);
"return"	return TOKEN(RETURN);
"let"           return TOKEN(LET);
"variadic"      return TOKEN(VARIADIC);
"struct"        return TOKEN(STRUCT);

"__cast"        return TOKEN(CAST);
"__fptr"        return TOKEN(FPTR);
"__asm"         return TOKEN(ASM);

":"             return TOKEN(COLON);

{int} 		return TOKEN_VAL(INT_LIT, std::atoi(yytext));
{hexint} 	return TOKEN_VAL(INT_LIT, std::strtol(yytext, NULL, 16));
{id} 		return TOKEN_VAL(ID, symbol(yytext));
{strlit} 	{return TOKEN_VAL(STR_LIT, /* Remove quotes */
			std::string(yytext + 1, strlen(yytext + 1) - 1)); }
. 		{
	std::cerr << "invalid character: " << yytext << '\n';
        COMPILATION_ERROR(utils::cfail::LEXING);
}

<<EOF>> 	return TOKEN(EOF);
%%

void driver::scan_begin() {
	yy_flex_debug = debug_scanning_;
	if (!(yyin = fopen(file_.c_str(), "r"))) {
		std::cerr << "cannot open " << file_ << ": " << strerror(errno)
			  << '\n';
		exit(EXIT_FAILURE);
	}
}

void driver::scan_end() { fclose(yyin); }
