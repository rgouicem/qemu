/*
 *  exit support for qemu
 *
 *  Copyright (c) 2018 Alex Bennée <alex.bennee@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu.h"
#ifdef CONFIG_GPROF
#include <sys/gmon.h>
#endif

#ifdef CONFIG_GCOV
extern void __gcov_dump(void);
#endif

uint64_t tb_lookup_time, tb_gen_code_time, exec_tb_time;

void preexit_cleanup(CPUArchState *env, int code)
{
    /* Dump profiling info */
    qemu_log_mask(PROF, "tb_lookup: %lu\n", tb_lookup_time);
    qemu_log_mask(PROF, "tb_gen_code: %lu\n", tb_gen_code_time);
    qemu_log_mask(PROF, "exec_tb: %lu\n", exec_tb_time);
#ifdef CONFIG_GPROF
    _mcleanup();
#endif
#ifdef CONFIG_GCOV
    __gcov_dump();
#endif
    gdb_exit(code);
    qemu_plugin_atexit_cb();
}
