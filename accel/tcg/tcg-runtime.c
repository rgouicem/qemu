/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "exec/log.h"
#include "tcg/tcg.h"
#include "tb-lookup.h"

#include <sys/syscall.h>

/* 32-bit helpers */

int32_t HELPER(div_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 / arg2;
}

int32_t HELPER(rem_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 % arg2;
}

uint32_t HELPER(divu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 / arg2;
}

uint32_t HELPER(remu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 % arg2;
}

/* 64-bit helpers */

uint64_t HELPER(shl_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 << arg2;
}

uint64_t HELPER(shr_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(sar_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(div_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 / arg2;
}

int64_t HELPER(rem_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(divu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 / arg2;
}

uint64_t HELPER(remu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(muluh_i64)(uint64_t arg1, uint64_t arg2)
{
    uint64_t l, h;
    mulu64(&l, &h, arg1, arg2);
    return h;
}

int64_t HELPER(mulsh_i64)(int64_t arg1, int64_t arg2)
{
    uint64_t l, h;
    muls64(&l, &h, arg1, arg2);
    return h;
}

uint32_t HELPER(clz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? clz32(arg) : zero_val;
}

uint32_t HELPER(ctz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? ctz32(arg) : zero_val;
}

uint64_t HELPER(clz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? clz64(arg) : zero_val;
}

uint64_t HELPER(ctz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? ctz64(arg) : zero_val;
}

uint32_t HELPER(clrsb_i32)(uint32_t arg)
{
    return clrsb32(arg);
}

uint64_t HELPER(clrsb_i64)(uint64_t arg)
{
    return clrsb64(arg);
}

uint32_t HELPER(ctpop_i32)(uint32_t arg)
{
    return ctpop32(arg);
}

uint64_t HELPER(ctpop_i64)(uint64_t arg)
{
    return ctpop64(arg);
}

const void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    tb = tb_lookup(cpu, pc, cs_base, flags, curr_cflags(cpu));
    if (tb == NULL) {
        return tcg_code_gen_epilogue;
    }
    qemu_log_mask_and_addr(CPU_LOG_EXEC, pc,
                           "Chain %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, tb->tc.ptr, cs_base, pc, flags,
                           lookup_symbol(pc));
    return tb->tc.ptr;
}

void HELPER(exit_atomic)(CPUArchState *env)
{
    cpu_loop_exit_atomic(env_cpu(env), GETPC());
}


/* #define MEM_ACCESS_HASHMAP_SIZE (1 << 16) */

/* struct mem_access_list { */
/*     struct mem_access *head; */
/*     pthread_rwlock_t lock; */
/*     uint64_t size; */
/* }; */

/* struct mem_access { */
/*     void *addr; */
/*     pid_t tid; */
/*     uint64_t count; */
/*     struct mem_access *next; */
/* }; */

/* static struct mem_access_list *mem_access_hashmap; */
/* /\* static uint64_t mem_access_clock; *\/ */

/* static inline void alloc_mem_access_hashmap(void) */
/* { */
/*     mem_access_hashmap = malloc(MEM_ACCESS_HASHMAP_SIZE * sizeof(struct mem_access_list)); */
/*     if (!mem_access_hashmap) { */
/*         perror("Failed to allocate hashmap\n"); */
/*         exit(-1); */
/*     } */
/*     for (int i = 0; i < MEM_ACCESS_HASHMAP_SIZE; i++) { */
/*         pthread_rwlock_init(&mem_access_hashmap[i].lock, NULL); */
/*     } */
/* } */

/* static inline void mem_access_add(uint64_t addr, pid_t tid) */
/* { */
/*     struct mem_access_list *list; */
/*     struct mem_access *item; */
/*     uint64_t hash; */
/*     bool writing = false; */

/*     /\* addr is shifted to do this at the page granularity *\/ */
/*     addr >>= 12; */
/*     hash = addr % MEM_ACCESS_HASHMAP_SIZE; */
/*     /\* check if this address has already been accessed by this tid *\/ */
/*     list = &mem_access_hashmap[hash]; */
/*     pthread_rwlock_rdlock(&list->lock); */
/* retry: */
/*     for (item = list->head; item; item = item->next) { */
/*         /\* addr already accessed by tid, increment count *\/ */
/*         if (item->addr == (void *)addr && item->tid == tid) { */
/*             __atomic_fetch_add(&item->count, 1, __ATOMIC_SEQ_CST); */
/*             goto end; */
/*         } */
/*     } */

/*     /\* addr never accessed by tid, create a new item in hashmap *\/ */
/*     /\* First, we check the list again with the write lock *\/ */
/*     if (!writing) { */
/*         pthread_rwlock_unlock(&list->lock); */
/*         pthread_rwlock_wrlock(&list->lock); */
/*         writing = true; */
/*         goto retry; */
/*     } */
/*     item = malloc(sizeof(struct mem_access)); */
/*     if (!item) { */
/*         perror("Failed to allocate a new item for hashmap\n"); */
/*         exit(-2); */
/*     } */
/*     item->addr = (void *)addr; */
/*     item->tid = tid; */
/*     item->count = 1; */
/*     item->next = mem_access_hashmap[hash].head; */
/*     list->head = item; */
/*     __atomic_fetch_add(&list->size, 1, __ATOMIC_SEQ_CST); */
/* end: */
/*     pthread_rwlock_unlock(&list->lock); */
/* } */

static inline void trace_tcg_ldst(uint64_t addr, const char *op)
{
    pid_t tid = syscall(SYS_gettid);
    struct timespec ts;

    /* if (unlikely(!mem_access_hashmap)) { */
    /*     alloc_mem_access_hashmap(); */
    /* } */

    clock_gettime(CLOCK_MONOTONIC, &ts);
    qemu_log_mask(LOG_ST_LD, "%ld.%ld;%d;%s;%p\n",
                  ts.tv_sec, ts.tv_nsec, tid, op, (void *)addr);
    /* mem_access_add(addr, tid); */
}

void HELPER(trace_tcg_st)(uint64_t addr)
{
    trace_tcg_ldst(addr, "s");
}

void HELPER(trace_tcg_ld)(uint64_t addr)
{
    trace_tcg_ldst(addr, "l");
}

/* void mem_access_hashmap_dump(void); */
/* void mem_access_hashmap_dump(void) */
/* { */
/*     struct mem_access *item; */

/*     for (int i = 0; i < MEM_ACCESS_HASHMAP_SIZE; i++) { */
/*         for (item = mem_access_hashmap[i].head; item; item = item->next) { */
/*             qemu_log_mask(LOG_ST_LD, "%d;%p;%lu\n", */
/*                           item->tid, item->addr, item->count); */
/*         } */
/*     } */
/* } */
