#ifndef LIBTCG_H
#define LIBTCG_H


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

struct libtcg_ctx {
    /* Source (guest) */
    uint64_t guest_size;
    uint64_t guest_icount;
    target_ulong *guest_insn_buffer;
    /* TCG IR */
    uint64_t tcg_size;
    uint64_t tcg_icount;
    /* Target (host) */
    uint64_t host_size;
    uint64_t host_icount;

    /* Private */
    CPUState *cpu;
};
typedef struct libtcg_ctx libtcg_ctx;

libtcg_ctx *init_libtcg(void);
int translate_tb_to_tcg(libtcg_ctx *ctx);

#endif  /* LIBTCG_H */
