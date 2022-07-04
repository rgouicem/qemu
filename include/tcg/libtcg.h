#ifndef LIBTCG_H
#define LIBTCG_H

struct libtcg_ctx {
    /* Source (guest) */
    uint64_t guest_size;
    uint64_t guest_icount;
    target_ulong guest_pc;
    target_ulong *guest_insn_buffer;
    /* TCG IR */
    uint64_t tcg_size;
    uint64_t tcg_icount;
    TCGOp   *tcg_insn;
    /* Target (host) */
    uint64_t host_size;
    uint64_t host_icount;

    /* Private */
    CPUState *cpu;
    CPUArchState *env;
};
typedef struct libtcg_ctx libtcg_ctx;

/* libtcg_ctx *init_libtcg(void); */
libtcg_ctx *init_libtcg(int argc, char **argv, char **envp);
int translate_tb_to_tcg(libtcg_ctx *ctx);
void tcg_dump_op(TCGOp *op, bool have_prefs);

#endif  /* LIBTCG_H */
