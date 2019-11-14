%{
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>

#include "driver.hh"
#include "parser.hh"
%}

%option noyywrap nounput noinput batch debug

%{
#define TOKEN_VAL(Type, Value) yy::parser::make_##Type(Value, d.location_)

#define TOKEN(Type) yy::parser::make_##Type(d.location_)

#define yyterminate() return TOKEN(EOF)
%}

id 	[a-zA-Z][a-zA-Z_0-9]*
int 	-?[0-9]+
blank 	[ \t\r]

%%

{blank}+ 	d.location_.step();
\n+ 	 	{ d.location_.lines(yyleng); d.location_.step(); }

"=" 		return TOKEN(ASSIGN);
"==" 		return TOKEN(EQ);
"-"	    	return TOKEN(MINUS);
"+"	    	return TOKEN(PLUS);
"*"	    	return TOKEN(MULT);
"/"	    	return TOKEN(DIV);
"("	    	return TOKEN(LPAREN);
")"	    	return TOKEN(RPAREN);

{int} 		return TOKEN_VAL(INT, std::atoi(yytext));
{id} 		return TOKEN_VAL(ID, symbol(yytext));

. 		{
	std::cerr << "invalid character: " << yytext << '\n';
	std::exit(2);
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
