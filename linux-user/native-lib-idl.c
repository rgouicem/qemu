#include "qemu/osdep.h"
#include "qemu.h"
#include "native-lib.h"
#include "native-lib-idl.h"

#include <stdio.h>
#include <stdlib.h>

extern int nlib_idl_parse(FILE *f);

void nlib_load_idl(const char *idlfile)
{
    FILE *f = fopen(idlfile, "r");
    if (!f)
    {
        fprintf(stderr, "nlib: unable to open idl file\n");
        exit(EXIT_FAILURE);
    }

    int rc = nlib_idl_parse(f);
    fclose(f);

    if (rc)
    {
        exit(EXIT_FAILURE);
    }
}

idl_ast_node *idl_alloc_ast_node(idl_ast_node_type ty)
{
    idl_ast_node *r = g_malloc(sizeof(idl_ast_node));
    r->ty = ty;
    r->children = NULL;
    r->nr_children = 0;
    r->value = NULL;

    return r;
}

void idl_add_child(idl_ast_node *parent, idl_ast_node *child)
{
    parent->children = g_realloc(parent->children, sizeof(idl_ast_node *) * (parent->nr_children + 1));
    parent->children[parent->nr_children] = child;
    parent->nr_children++;
}

void idl_commit(idl_ast_node *root)
{
    idl_ast_node *defs = root->children[0];

    const char *curlib = NULL;
    for (int i = 0; i < defs->nr_children; i++) {
        idl_ast_node *def = defs->children[i];
        if (def->ty == IANT_LIBDEF) {
            curlib = def->value;
        } else if (def->ty == IANT_FNDEF) {
            nlib_function *fn = nlib_add_function(def->value, curlib);

            if (def->nr_children == 0) {
                fprintf(stderr, "nlib: idl: invalid function definition\n");
                exit(1);
            }

            idl_ast_node *rv = def->children[0];
            nlib_fn_set_ret(fn, rv->tc, rv->width, rv->is_const);

            if (def->nr_children > 1) {
                idl_ast_node *params = def->children[1];
                for (int j = 0; j < params->nr_children; j++) {
                    idl_ast_node *param = params->children[j];
                    idl_ast_node *ptd = param->children[0];

                    nlib_fn_add_arg(fn, ptd->tc, ptd->width, ptd->is_const);
                }
            }
        } else {
            fprintf(stderr, "nlib: idl: unknown definition type\n");
            exit(1);
        }
    }
}

#if 0
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * idl  : defs
 * defs : def defs
 *      |
 * def  : libdef
 *      | fndef
 *      | cmndef
 * libdef : `library` libname `;`
 * libname : `"` .* `"`
 * fndef : ctypedef fname `(` params `)` `;`
 * typedef : `i8` | `i16` | `i32` | `i64` | `ilong` | `u1` | `u8` | `u16` | `u32` | `u64` | `ulong` | `f32` | `f64` | `fd` | `string` | ptrdef
 * ctypedef: typedef | `const` typedef
 * ptrdef : `ptr` | `ptr` `(` paramname `)`
 * params : params `,` param
 *        | param
 *        |
 * param : ctypedef paramname
 * paramname: [A-Za-z]+[A-Za-z0-9]*
 */

typedef enum
{
    T_LIBRARY,
    T_SEMI,
    T_DOT,
    T_LPAREN,
    T_RPAREN,
    T_I8,
    T_I
} parse_tokens;

typedef struct
{
    char *current_library;
    nlib_function *current_function;
} idl_context;

typedef struct
{
    nlib_type_class tc;
    int width;
    int cnst;
} typedef_descr;

typedef struct
{
    FILE *f;
    int c;
    int line, col;
    int eof;
    idl_context idl;
} parse_context;

static int parse_error(parse_context *pc, const char *msg)
{
    fprintf(stderr, "nlib: idl file parse error: %s (%d:%d)\n", msg, pc->line, pc->col);
    return 1;
}

static char peek(parse_context *pc)
{
    return pc->c;
}

static char consume(parse_context *pc)
{
    char c = pc->c;
    pc->c = fgetc(pc->f);
    if (feof(pc->f))
    {
        pc->eof = 1;
    }

    if (c == '\n')
    {
        pc->col = 1;
        pc->line++;
    }
    else
    {
        pc->col++;
    }

    return c;
}

static int expect(parse_context *pc, char c)
{
    if (consume(pc) != c)
    {
        char buffer[32];
        snprintf(buffer, 31, "expected '%c'", c);
        return parse_error(pc, buffer);
    }

    return 0;
}

/*static int match(parse_context *pc, char c)
{
    if (peek(pc) == c) {
        consume(pc);
        return 1;
    }

    return 0;
}*/


static int expect_str(parse_context *pc, const char *str)
{
    int rc;

    do
    {
        rc = expect(pc, *str++);
    } while (*str && !rc);

    return rc;
}

static void skip_whitespace(parse_context *pc)
{
    while (isspace(peek(pc)))
    {
        consume(pc);
    }
}

static int parse_libname(parse_context *pc)
{
    if (consume(pc) != '"')
    {
        return parse_error(pc, "expected '\"'");
    }

    int n = 0;
    char buffer[256];

    while (peek(pc) != '"')
    {
        buffer[n++] = consume(pc);
    }
    buffer[n] = 0;

    if (consume(pc) != '"')
    {
        return parse_error(pc, "expected '\"'");
    }

    if (pc->idl.current_library)
    {
        free(pc->idl.current_library);
    }

    pc->idl.current_library = strdup(buffer);
    return 0;
}

static int parse_libdef(parse_context *pc)
{
    if (expect_str(pc, "library"))
    {
        return 1;
    }

    skip_whitespace(pc);

    int rc = parse_libname(pc);
    if (rc)
    {
        return rc;
    }

    if (consume(pc) != ';')
    {
        return parse_error(pc, "expected ';'");
    }

    return 0;
}

static int parse_cmndef(parse_context *pc)
{
    if (consume(pc) != '#')
    {
        return parse_error(pc, "expected '#'");
    }

    while (peek(pc) != '\n')
    {
        consume(pc);
    }

    return 0;
}

// paramname: [A-Za-z]+[A-Za-z0-9]*
static int parse_paramname(parse_context *pc, char **out)
{
    char buffer[512];
    int n = 0;

    if (!isalpha(peek(pc)))
    {
        return parse_error(pc, "expected alpha");
    }

    buffer[n++] = consume(pc);
    while (isalnum(peek(pc)))
    {
        buffer[n++] = consume(pc);
    }
    buffer[n] = 0;

    *out = strdup(buffer);
    return 0;
}

// typedef : `i8` | `i16` | `i32` | `i64` | `ilong` | `u1` | `u8` | `u16` | `u32` | `u64` | `ulong` | `f32` | `f64` | `fd` | `string` | `cplx` | ptrdef
// ptrdef : `ptr` | `ptr` `(` paramname `)`
static int parse_ptrdef(parse_context *pc, typedef_descr *td)
{
    if (consume(pc) != 'p')
    {
        return parse_error(pc, "expected 'p'");
    }

    if (consume(pc) != 't')
    {
        return parse_error(pc, "expected 't'");
    }

    if (consume(pc) != 'r')
    {
        return parse_error(pc, "expected 'r'");
    }

    skip_whitespace(pc);

    td->tc = NLTC_MEMPTR;
    td->width = 64;

    if (peek(pc) == '(')
    {
        if (consume(pc) != '(')
        {
            return parse_error(pc, "expected '('");
        }

        skip_whitespace(pc);

        char *pname;
        int rc = parse_paramname(pc, &pname);
        if (rc)
        {
            return rc;
        }

        free(pname);

        skip_whitespace(pc);

        if (consume(pc) != ')')
        {
            return parse_error(pc, "expected '('");
        }
    }

    return 0;
}

static int parse_typedef(parse_context *pc, typedef_descr *td)
{
    switch (peek(pc))
    {
    case 'i':
    case 'u':
    case 'f':
    case 's':
    case 'v':
    case 'c':
        break;

    case 'p':
        return parse_ptrdef(pc, td);
    }

    char buffer[512];
    int n = 0;

    while (isalnum(peek(pc)))
    {
        buffer[n++] = consume(pc);
    }
    buffer[n] = 0;

    if (!strcmp(buffer, "void"))
    {
        td->tc = NLTC_VOID;
        td->width = 0;
    }
    else if (!strcmp(buffer, "cplx"))
    {
        td->tc = NLTC_CPLX;
        td->width = 0;
    }
    else if (!strcmp(buffer, "i8"))
    {
        td->tc = NLTC_SINT;
        td->width = 8;
    }
    else if (!strcmp(buffer, "i16"))
    {
        td->tc = NLTC_SINT;
        td->width = 16;
    }
    else if (!strcmp(buffer, "i32"))
    {
        td->tc = NLTC_SINT;
        td->width = 32;
    }
    else if (!strcmp(buffer, "i64") || !strcmp(buffer, "ilong"))
    {
        td->tc = NLTC_SINT;
        td->width = 64;
    }
    else if (!strcmp(buffer, "u1"))
    {
        td->tc = NLTC_UINT;
        td->width = 1;
    }
    else if (!strcmp(buffer, "u8"))
    {
        td->tc = NLTC_UINT;
        td->width = 8;
    }
    else if (!strcmp(buffer, "u16"))
    {
        td->tc = NLTC_UINT;
        td->width = 16;
    }
    else if (!strcmp(buffer, "u32"))
    {
        td->tc = NLTC_UINT;
        td->width = 32;
    }
    else if (!strcmp(buffer, "u64") || !strcmp(buffer, "ulong"))
    {
        td->tc = NLTC_UINT;
        td->width = 64;
    }
    else if (!strcmp(buffer, "f32"))
    {
        td->tc = NLTC_FLOAT;
        td->width = 32;
    }
    else if (!strcmp(buffer, "f64"))
    {
        td->tc = NLTC_FLOAT;
        td->width = 64;
    }
    else if (!strcmp(buffer, "fd"))
    {
        td->tc = NLTC_FD;
        td->width = 64;
    }
    else if (!strcmp(buffer, "fnptr"))
    {
        td->tc = NLTC_FNPTR;
        td->width = 64;
    }
    else if (!strcmp(buffer, "string"))
    {
        td->tc = NLTC_STRING;
        td->width = 64;
    }
    else
    {
        return parse_error(pc, "unknown type");
    }

    return 0;
}

static int parse_ctypedef(parse_context *pc, typedef_descr *td)
{
    td->cnst = 0;
    if (peek(pc) == 'c')
    {
        if (consume(pc) != 'c')
        {
            return parse_error(pc, "expected 'c'");
        }

        if (peek(pc) == 'p') {
            // cplx

            if (consume(pc) != 'p')
            {
                return parse_error(pc, "expected 'p'");
            }
            if (consume(pc) != 'l')
            {
                return parse_error(pc, "expected 'l'");
            }
            if (consume(pc) != 'x')
            {
                return parse_error(pc, "expected 'x'");
            }

            td->tc = NLTC_CPLX;
            td->width = 0;

            return 0;
        } else {
            // onst

            if (consume(pc) != 'o')
            {
                return parse_error(pc, "expected 'o'");
            }
            if (consume(pc) != 'n')
            {
                return parse_error(pc, "expected 'n'");
            }
            if (consume(pc) != 's')
            {
                return parse_error(pc, "expected 's'");
            }
            if (consume(pc) != 't')
            {
                return parse_error(pc, "expected 't'");
            }

            td->cnst = 1;
            skip_whitespace(pc);
        }
    }

    return parse_typedef(pc, td);
}

static int isalund(int c)
{
    return isalpha(c) || c == '_';
}

static int isalnumund(int c)
{
    return isalnum(c) || c == '_';
}

static int parse_fname(parse_context *pc, char **out)
{
    if (!isalund(peek(pc)))
    {
        return parse_error(pc, "expected alpha/underscore character");
    }

    char buffer[512];
    int n = 0;

    buffer[n++] = consume(pc);
    while (isalnumund(peek(pc)))
    {
        buffer[n++] = consume(pc);
    }
    buffer[n] = 0;

    *out = strdup(buffer);
    return 0;
}

// param : typedef paramname
static int parse_param(parse_context *pc)
{
    typedef_descr td;

    int rc = parse_ctypedef(pc, &td);
    if (rc)
    {
        return rc;
    }

    skip_whitespace(pc);

    char *paramname;
    rc = parse_paramname(pc, &paramname);
    if (rc)
    {
        return rc;
    }

    nlib_fn_add_arg(pc->idl.current_function, td.tc, td.width, td.cnst);

    free(paramname);
    return 0;
}

// params : param `,` params
//        | param
//        |

static int parse_params(parse_context *pc)
{
    switch (peek(pc))
    {
    case 'i':
    case 'u':
    case 'f':
    case 's':
    case 'p':
    case 'c':
    case 'v':
    {
        int rc = parse_param(pc);
        if (rc)
        {
            return rc;
        }

        skip_whitespace(pc);

        if (peek(pc) == ',')
        {
            consume(pc);
            skip_whitespace(pc);
            return parse_params(pc);
        }

        return 0;
    }

    default:
        return 0;
    }
}

// fndef : ctypedef fname `(` params `)` `;`
static int parse_fndef(parse_context *pc)
{
    if (!pc->idl.current_library)
    {
        return parse_error(pc, "no current library");
    }

    typedef_descr td;

    int rc = parse_ctypedef(pc, &td);
    if (rc)
    {
        return rc;
    }

    skip_whitespace(pc);

    char *fname;
    rc = parse_fname(pc, &fname);
    if (rc)
    {
        return rc;
    }

    pc->idl.current_function = nlib_add_function(fname, pc->idl.current_library);
    nlib_fn_set_ret(pc->idl.current_function, td.tc, td.width, td.cnst);

    free(fname);

    skip_whitespace(pc);

    if (consume(pc) != '(')
    {
        return parse_error(pc, "expected '('");
    }

    skip_whitespace(pc);

    rc = parse_params(pc);
    if (rc)
    {
        return rc;
    }

    skip_whitespace(pc);

    if (consume(pc) != ')')
    {
        return parse_error(pc, "expected ')'");
    }

    skip_whitespace(pc);

    if (consume(pc) != ';')
    {
        return parse_error(pc, "expected ';'");
    }

    return 0;
}

static int parse_def(parse_context *pc)
{
    switch (peek(pc))
    {
    case 'l':
        return parse_libdef(pc);

    case '#':
        return parse_cmndef(pc);

    case 'i':
    case 'u':
    case 'f':
    case 's':
    case 'p':
    case 'c':
    case 'v':
        return parse_fndef(pc);

    default:
    {
        char buffer[32];
        snprintf(buffer, 31, "unexpected char '%c'", peek(pc));
        return parse_error(pc, buffer);
    }
    }
}

static int parse_defs(parse_context *pc)
{
    skip_whitespace(pc);

    if (pc->eof)
    {
        return 0;
    }

    switch (peek(pc))
    {
    case 'l':
    case '#':
    case 'i':
    case 'u':
    case 'f':
    case 's':
    case 'p':
    case 'c':
    case 'v':
    {
        int rc = parse_def(pc);
        if (rc)
        {
            return rc;
        }

        return parse_defs(pc);
    }

    default:
        return parse_error(pc, "unexpected char");
    }

    return 0;
}

static int parse_idl(parse_context *pc)
{
    return parse_defs(pc);
}

static int parse(parse_context *pc)
{
    return parse_idl(pc);
}

void nlib_load_idl(const char *idlfile)
{
    parse_context pc;
    memset(&pc, 0, sizeof(pc));

    pc.f = fopen(idlfile, "r");
    if (!pc.f)
    {
        fprintf(stderr, "nlib: unable to open idl file\n");
        exit(EXIT_FAILURE);
    }

    pc.line = 1;
    pc.col = 0;

    consume(&pc);
    int rc = parse(&pc);

    fclose(pc.f);

    if (rc)
    {
        fprintf(stderr, "nlib: idl error\n");
        exit(EXIT_FAILURE);
    }
}
#endif
