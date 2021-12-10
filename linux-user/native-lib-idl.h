#ifndef NATIVE_LIB_IDL_H
#define NATIVE_LIB_IDL_H

typedef enum {
    IANT_ROOT,
    IANT_DEFS,
    IANT_LIBDEF,
    IANT_CCDEF,
    IANT_FNDEF,
    IANT_TYPEDEF,
    IANT_PARAMS,
    IANT_PARAM,
    IANT_ATTRS,
    IANT_ATTR
} idl_ast_node_type;

struct idl_ast_node {
    idl_ast_node_type ty;
    struct idl_ast_node **children;
    int nr_children;

    const char *value;
    int is_const;
    int width;
    int tc;
};

typedef struct idl_ast_node idl_ast_node;

idl_ast_node *idl_alloc_ast_node(idl_ast_node_type ty);
void idl_add_child(idl_ast_node *parent, idl_ast_node *child);
void idl_commit(idl_ast_node *root);
#endif
