%option noyywrap

%{
#include <stdio.h>
#include "native-lib-idl.h"
#include "native-lib-idl.tab.h"

#pragma GCC diagnostic ignored "-Wunused-function"

int linenum = 1;
%}

%x comment str

%%

"#" BEGIN(comment);
"\"" BEGIN(str);

"library" { return T_LIBRARY; }
"callconv" { return T_CALLCONV; }

"i8" { return T_I8; }
"i16" { return T_I16; }
"i32" { return T_I32; }
"i64" { return T_I64; }
"ilong" { return T_ILONG; }
"u1" { return T_U1; }
"u8" { return T_U8; }
"u16" { return T_U16; }
"u32" { return T_U32; }
"u64" { return T_U64; }
"ulong" { return T_ULONG; }
"f32" { return T_F32; }
"f64" { return T_F64; }

"string" { return T_STRING; }
"fd" { return T_FD; }
"cplx" { return T_CPLX; }
"const" { return T_CONST; }
"void" { return T_VOID; }
"ptr" { return T_PTR; }

"(" { return T_LPAREN; }
")" { return T_RPAREN; }
"[" { return T_LBRACKET; }
"]" { return T_RBRACKET; }
";" { return T_SEMI; }
"," { return T_COMMA; }
"*" { return T_STAR; }

[a-zA-Z_][a-zA-Z0-9_]* { yylval.text = strdup(yytext); return IDENTIFIER; }
[ \t\r]+ {}
\n {++linenum;}

<comment>[^\n]* {};
<comment>\n { BEGIN(INITIAL); ++linenum; }

<str>[^\"]* { yylval.text = strdup(yytext); return STRING_LITERAL; }
<str>\" { BEGIN(INITIAL); }
%%
