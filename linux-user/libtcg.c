
#include "tcg/libtcg.h"

int translate_tb_to_tcg(libtcg_ctx *ctx)
{
    CPUState *cpu;
    /* CPUArchState *env; */
    AccelClass *ac = ACCEL_GET_CLASS(current_accel());
    target_ulong cs_base, pc;
    uint32_t flags, cflags;
    TranslationBlock *tb;

    accel_init_interfaces(ac);
    ac->init_machine(NULL);

    cpu = cpu_create("any");
    /* env = cpu->env_ptr; */
    cpu_reset(cpu);

    qemu_set_log(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT);

    cpu_get_tb_cpu_state(cpu->env_ptr, &pc, &cs_base, &flags);
    cflags = curr_cflags(cpu);

    tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
    ctx->tcg_icount = tb->icount;
    ctx->tcg_size = tb->size;

    return 0;
}

libtcg_ctx *alloc_libtcg_ctx(void)
{
    libtcg_ctx *ctx = malloc(sizeof(libtcg_ctx));

    return ctx;
}
