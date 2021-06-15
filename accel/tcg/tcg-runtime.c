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

#define MEM_ACCESS_HASHMAP_SIZE 128
#define MEM_ACCESS_MMAP_SIZE    (1 << 26)

struct mem_access {
    uint64_t addr;
    uint64_t time;
};

struct mem_access_bucket {
    struct mem_access *array;
    uint64_t count;
    pid_t tid;
    int fd;
    int rounds;
    char *path;
};

static struct mem_access_bucket *mem_access_hashmap;
const char *stld_dir_path;

static struct mem_access_bucket *alloc_mem_access_hashmap(void)
{
    struct mem_access_bucket *hm = calloc(MEM_ACCESS_HASHMAP_SIZE,
                                          sizeof(struct mem_access_bucket));

    if (!hm) {
        perror("Failed to allocate hashmap");
        exit(2);
    }

    return hm;
}

static inline void init_mem_access_bucket(struct mem_access_bucket *bucket, pid_t tid)
{
    size_t namelen = strlen(stld_dir_path) + 10;

    bucket->path = malloc(namelen);
    if (!bucket->path) {
        perror("Failed to allocate hashmap bucket");
        exit(2);
    }

    bucket->tid = tid;

    snprintf(bucket->path, namelen,
             "%s/%d",
             stld_dir_path, tid);
    bucket->fd = open(bucket->path, O_CREAT | O_APPEND | O_RDWR | O_TRUNC,
                      0664);
    if (bucket->fd == -1) {
        perror("Failed to open file");
        exit(-2);
    }
    if (truncate(bucket->path,
                 MEM_ACCESS_MMAP_SIZE * sizeof(struct mem_access))) {
        perror("Truncate failed");
        exit(2);
    }

    bucket->array = mmap(NULL, MEM_ACCESS_MMAP_SIZE * sizeof(struct mem_access),
                         PROT_READ | PROT_WRITE, MAP_SHARED, bucket->fd, 0);
    if (bucket->array == MAP_FAILED) {
        perror("Failed to mmap array");
        exit(2);
    }
}

static void mem_access_bucket_remap(struct mem_access_bucket *bucket)
{
    /* Unmap previous memory area */
    if (munmap(bucket->array, MEM_ACCESS_MMAP_SIZE)) {
        perror("munmap");
        exit(2);
    }
    bucket->rounds++;

    /* Map the following region in the file */
    if (truncate(bucket->path,
                 bucket->rounds * MEM_ACCESS_MMAP_SIZE * sizeof(struct mem_access))) {
        perror("Re-truncate failed");
        exit(2);
    }
    bucket->array = mmap(NULL, MEM_ACCESS_MMAP_SIZE * sizeof(struct mem_access),
                         PROT_READ | PROT_WRITE, MAP_SHARED, bucket->fd,
                         bucket->rounds * MEM_ACCESS_MMAP_SIZE * sizeof(struct mem_access));
    if (bucket->array == MAP_FAILED) {
        perror("Failed to remmap array");
        exit(2);
    }
    bucket->count = 0;
}

static inline void mem_access_add(uint64_t addr, pid_t tid)
{
    int hash = tid % MEM_ACCESS_HASHMAP_SIZE;
    struct mem_access_bucket *bucket = mem_access_hashmap + hash;
    struct timespec ts;

    if (unlikely(bucket->tid == 0)) {
        init_mem_access_bucket(bucket, tid);
    }

    if (unlikely(bucket->tid != tid)) {
        perror("Hashmap collision");
        exit(2);
    }

    /* If the curent mmap is full, remap */
    if (unlikely(bucket->count == MEM_ACCESS_MMAP_SIZE)) {
        mem_access_bucket_remap(bucket);
    }

    /* commit the memory access to array */
    bucket->array[bucket->count].addr = addr;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    bucket->array[bucket->count].time = ts.tv_sec * 1E9 + ts.tv_nsec;

    bucket->count++;
}

static inline void trace_tcg_ldst(uint64_t addr, const char *op)
{
    pid_t tid = syscall(SYS_gettid);

    if (unlikely(!mem_access_hashmap)) {
        mem_access_hashmap = alloc_mem_access_hashmap();
    }

    mem_access_add(addr, tid);
}

void HELPER(trace_tcg_st)(uint64_t addr)
{
    trace_tcg_ldst(addr, "s");
}

void HELPER(trace_tcg_ld)(uint64_t addr)
{
    trace_tcg_ldst(addr, "l");
}
