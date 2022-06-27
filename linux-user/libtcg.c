
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/units.h"
#include "qemu/accel.h"
#include "sysemu/tcg.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <linux/binfmts.h>

#include "qapi/error.h"
#include "qemu.h"
#include "user-internals.h"
#include "qemu/path.h"
#include "qemu/queue.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu/plugin.h"
#include "exec/exec-all.h"
#include "exec/gdbstub.h"
#include "tcg/tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "qemu/guest-random.h"
#include "elf.h"
#include "trace/control.h"
#include "target_elf.h"
#include "cpu_loop-common.h"
#include "crypto/init.h"
#include "fd-trans.h"
#include "signal-common.h"
#include "loader.h"
#include "user-mmap.h"
#include "../accel/tcg/internal.h"

#include "tcg/libtcg.h"

int translate_block(target_ulong *block_inst)
{
    CPUState *cpu;
    /* CPUArchState *env; */
    AccelClass *ac = ACCEL_GET_CLASS(current_accel());
    target_ulong cs_base, pc;
    uint32_t flags, cflags;

    accel_init_interfaces(ac);
    ac->init_machine(NULL);

    cpu = cpu_create("any");
    /* env = cpu->env_ptr; */
    cpu_reset(cpu);

    qemu_set_log(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT);

    cpu_get_tb_cpu_state(cpu->env_ptr, &pc, &cs_base, &flags);
    cflags = curr_cflags(cpu);

    tb_gen_code(cpu, pc, cs_base, flags, cflags);

    return 0;
}
