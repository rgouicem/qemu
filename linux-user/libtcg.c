
#include "tcg/libtcg.h"


static const char *argv0;
static const char *gdbstub;
static envlist_t *envlist;
static const char *cpu_model;

int translate_tb_to_tcg(libtcg_ctx *ctx)
{
    CPUState *cpu = ctx->cpu;
    /* CPUArchState *env = ctx->env; */
    target_ulong cs_base, pc;
    uint32_t flags, cflags;
    TranslationBlock *tb;

    cpu_get_tb_cpu_state(cpu->env_ptr, &pc, &cs_base, &flags);
    cflags = curr_cflags(cpu);

    tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
    ctx->tcg_icount = tb->icount;
    ctx->tcg_size = tb->size;

    return 0;
}

/* libtcg_ctx *init_libtcg(void) */
/* { */
/*     AccelClass *ac; */
/*     libtcg_ctx *ctx; */

/*     qemu_init_cpu_list(); */
/*     module_call_init(MODULE_INIT_QOM); */

/*     ac = ACCEL_GET_CLASS(current_accel()); */
/*     accel_init_interfaces(ac); */
/*     ac->init_machine(NULL); */

/*     ctx = malloc(sizeof(libtcg_ctx)); */
/*     if (!ctx) { */
/*         return NULL; */
/*     } */
/*     ctx = memset(ctx, 0, sizeof(libtcg_ctx)); */

/*     ctx->cpu = cpu_create(parse_cpu_option("qemu64")); */
/*     ctx->env = ctx->cpu->env_ptr; */
/*     cpu_reset(ctx->cpu); */

/*     qemu_set_log(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT); */


/*     return ctx; */
/* } */

libtcg_ctx *init_libtcg(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;
    int execfd;
    int log_mask;
    unsigned long max_reserved_va;
    bool preserve_argv0;
    libtcg_ctx *ctx;

    error_init(argv[0]);
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /*
     * Read the stack limit from the kernel.  If it's "unlimited",
     * then we can do little else besides use the default.
     */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    qemu_add_opts(&qemu_trace_opts);
    qemu_plugin_add_opts();

    optind = parse_args(argc, argv);

    log_mask = last_log_mask | (enable_strace ? LOG_STRACE : 0);
    if (log_mask) {
        qemu_log_needs_buffers();
        qemu_set_log(log_mask);
    }

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file();
    qemu_plugin_load_list(&plugins, &error_fatal);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof(bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    init_qemu_uname_release();

    /*
     * Manage binfmt-misc open-binary flag
     */
    execfd = qemu_getauxval(AT_EXECFD);
    if (execfd == 0) {
        execfd = open(exec_path, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", exec_path, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }

    /*
     * get binfmt_misc flags
     */
    preserve_argv0 = !!(qemu_getauxval(AT_FLAGS) & AT_FLAGS_PRESERVE_ARGV0);

    /*
     * Manage binfmt-misc preserve-arg[0] flag
     *    argv[optind]     full path to the binary
     *    argv[optind + 1] original argv[0]
     */
    if (optind + 1 < argc && preserve_argv0) {
        optind++;
    }

    if (cpu_model == NULL) {
        cpu_model = cpu_get_model(get_elf_eflags(execfd));
    }
    cpu_type = parse_cpu_option(cpu_model);

    /* init tcg before creating CPUs and to get qemu_host_page_size */
    {
        AccelClass *ac = ACCEL_GET_CLASS(current_accel());

        accel_init_interfaces(ac);
        ac->init_machine(NULL);
    }
    cpu = cpu_create(cpu_type);
    env = cpu->env_ptr;
    cpu_reset(cpu);
    thread_cpu = cpu;

    /*
     * Reserving too much vm space via mmap can run into problems
     * with rlimits, oom due to page table creation, etc.  We will
     * still try it, if directed by the command-line option, but
     * not by default.
     */
    max_reserved_va = MAX_RESERVED_VA(cpu);
    if (reserved_va != 0) {
        if (max_reserved_va && reserved_va > max_reserved_va) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    } else if (HOST_LONG_BITS == 64 && TARGET_VIRT_ADDR_SPACE_BITS <= 32) {
        /*
         * reserved_va must be aligned with the host page size
         * as it is used with mmap()
         */
        reserved_va = max_reserved_va & qemu_host_page_mask;
    }

    {
        Error *err = NULL;
        if (seed_optarg != NULL) {
            qemu_guest_random_seed_main(seed_optarg, &err);
        } else {
            qcrypto_init(&err);
        }
        if (err) {
            error_reportf_err(err, "cannot initialize crypto: ");
            exit(1);
        }
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        fp = fopen("/proc/sys/vm/mmap_min_addr", "r");
        if (fp != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1 && tmp != 0) {
                mmap_min_addr = tmp;
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n",
                              mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * We prefer to not make NULL pointers accessible to QEMU.
     * If we're in a chroot with no /proc, fall back to 1 page.
     */
    if (mmap_min_addr == 0) {
        mmap_min_addr = qemu_host_page_size;
        qemu_log_mask(CPU_LOG_PAGE,
                      "host mmap_min_addr=0x%lx (fallback)\n",
                      mmap_min_addr);
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof(char *));
    if (target_argv == NULL) {
        (void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
        exit(EXIT_FAILURE);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

    fd_trans_init();

    ret = loader_exec(execfd, exec_path, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", exec_path, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }

    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  %p\n", (void *)guest_base);
        log_page_dump("binary load");

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n", info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n", info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n", info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
        qemu_log("argv_start  0x" TARGET_ABI_FMT_lx "\n", info->arg_start);
        qemu_log("env_start   0x" TARGET_ABI_FMT_lx "\n",
                 info->arg_end + (abi_ulong)sizeof(abi_ulong));
        qemu_log("auxv_start  0x" TARGET_ABI_FMT_lx "\n", info->saved_auxv);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

    /*
     * Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
     * generating the prologue until now so that the prologue can take
     * the real value of GUEST_BASE into account.
     */
    tcg_prologue_init(tcg_ctx);

    target_cpu_copy_regs(env, regs);

    if (gdbstub) {
        if (gdbserver_start(gdbstub) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on %s\n",
                    gdbstub);
            exit(EXIT_FAILURE);
        }
        gdb_handlesig(cpu, 0);
    }
    /* cpu_loop(env); */
    /* never exits */

    ctx = malloc(sizeof(libtcg_ctx));
    if (!ctx) {
        return NULL;
    }
    ctx = memset(ctx, 0, sizeof(libtcg_ctx));

    ctx->cpu = cpu;
    ctx->env = env;

    return ctx;
}
