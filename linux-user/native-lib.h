#ifndef NATIVE_LIB_H
#define NATIVE_LIB_H

typedef enum
{
    NLTC_VOID,
    NLTC_SINT,
    NLTC_UINT,
    NLTC_FLOAT,
    NLTC_STRING,
    NLTC_MEMPTR,
    NLTC_FNPTR,
    NLTC_FD,
    NLTC_CPLX
} nlib_type_class;

typedef struct
{
    nlib_type_class tc;
    int width;
    int cnst;
} nlib_type;

typedef struct
{
    const char *fname;
    const char *libname;

    void *mdl;
    void *fnptr;

    nlib_type retty;
    nlib_type *argty;
    int nr_args;
} nlib_function;

void nlib_init(void);
void nlib_load_idl(const char *idlfile);
nlib_function *nlib_add_function(const char *fname, const char *libname);
nlib_function *nlib_lookup_function(unsigned int idx);
void nlib_fn_set_ret(nlib_function *fn, nlib_type_class tc, int width, int cnst);
void nlib_fn_add_arg(nlib_function *fn, nlib_type_class tc, int width, int cnst);
void nlib_register_txln_hook(unsigned long va, const char *fname);
nlib_function *nlib_get_txln_hook(unsigned long va);
#endif
