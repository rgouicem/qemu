#include "qemu/osdep.h"
#include "qemu.h"
#include "native-lib.h"

#include <gmodule.h>

static nlib_function **native_functions;
static unsigned int nr_native_functions;
static GHashTable *txln_hooks;

/**
 * Initialises the Native Library infrastructure
 */
void nlib_init(void)
{
    txln_hooks = g_hash_table_new(NULL, NULL);
}

/**
 * Registers a function to be redirected to native code from a guest
 * shared-library invocation.
 */
nlib_function *nlib_add_function(const char *fname, const char *libname)
{
    // Allocate storage for the native function descriptor.
    nlib_function *fn = g_malloc(sizeof(nlib_function));

    // Zero out the structure.
    memset(fn, 0, sizeof(*fn));

    // Copy in the function details that we know at this time.
    fn->fname = g_strdup(fname);
    fn->libname = g_strdup(libname);
    fn->mdl = g_module_open(fn->libname, 0);
    if (!fn->mdl) {
        fprintf(stderr, "nlib: could not open module '%s'\n", libname);
        exit(EXIT_FAILURE);
    }

    // Attempt to resolve the function symbol from the module.
    if (!g_module_symbol((GModule *)fn->mdl, fn->fname, &fn->fnptr)) {
        fprintf(stderr, "nlib: could not resolve function %s\n", fn->fname);
        exit(EXIT_FAILURE);
    }

    // Add the new function to the list.
    nr_native_functions++;
    native_functions = g_realloc(native_functions, sizeof(nlib_function *) * nr_native_functions);
    native_functions[nr_native_functions-1] = fn;

    return fn;
}

/**
 * Looks up a function from the registered function list, given an index.
 */
nlib_function *nlib_lookup_function(unsigned int idx)
{
    if (idx >= nr_native_functions) {
        return NULL;
    }

    return native_functions[idx];
}

/**
 * Sets the metadata for the return type of the function.
 */
void nlib_fn_set_ret(nlib_function *fn, nlib_type_class tc, int width, int cnst)
{
    fn->retty.tc = tc;
    fn->retty.width = width;
    fn->retty.cnst = cnst;
}

/**
 * Adds new argument metadata to the function.
 */
void nlib_fn_add_arg(nlib_function *fn, nlib_type_class tc, int width, int cnst)
{
    fn->nr_args++;
    fn->argty = g_realloc(fn->argty, sizeof(nlib_type) * fn->nr_args);

    nlib_type *t = &fn->argty[fn->nr_args-1];

    t->tc = tc;
    t->width = width;
    t->cnst = cnst;
}

/**
 * Registers a translation hook for catching guest shared-library invocations.
 */
void nlib_register_txln_hook(target_ulong va, const char *fname)
{
    nlib_function *fn = NULL;

    for (int i = 0; i < nr_native_functions; i++) {
        if (!strcmp(native_functions[i]->fname, fname)) {
            fn = native_functions[i];
            break;
        }
    }

    if (!fn) {
        return;
    }

    g_hash_table_insert(txln_hooks, (gpointer)va, (gpointer)fn);
}

/**
 * Looks up a corresponding native library function, given the registered
 * guest virtual address.
 */
nlib_function *nlib_get_txln_hook(target_ulong va)
{
    return (nlib_function *)g_hash_table_lookup(txln_hooks, (gconstpointer)va);
}
