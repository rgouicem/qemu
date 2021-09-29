linux_user_ss.add(files(
  'elfload.c',
  'exit.c',
  'fd-trans.c',
  'linuxload.c',
  'main.c',
  'mmap.c',
  'native-lib.c',
  'native-lib-idl.c',
  'safe-syscall.S',
  'signal.c',
  'strace.c',
  'syscall.c',
  'uaccess.c',
  'uname.c',
))
linux_user_ss.add(rt)

linux_user_ss.add(when: 'TARGET_HAS_BFLT', if_true: files('flatload.c'))
linux_user_ss.add(when: 'TARGET_I386', if_true: files('vm86.c'))
linux_user_ss.add(when: 'CONFIG_ARM_COMPATIBLE_SEMIHOSTING', if_true: files('semihost.c'))

flex = find_program('flex')
bison = find_program('bison')

lgen = generator(flex,
output : '@PLAINNAME@.yy.c',
arguments : ['-o', '@OUTPUT@', '@INPUT@'])

linux_user_ss.add(lgen.process('native-lib-idl.l'))

pgen = generator(bison,
output : ['@BASENAME@.tab.c', '@BASENAME@.tab.h'],
arguments : ['@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'])

linux_user_ss.add(pgen.process('native-lib-idl.y'))

syscall_nr_generators = {}

subdir('alpha')
subdir('arm')
subdir('hppa')
subdir('i386')
subdir('m68k')
subdir('microblaze')
subdir('mips64')
subdir('mips')
subdir('ppc')
subdir('s390x')
subdir('sh4')
subdir('sparc')
subdir('x86_64')
subdir('xtensa')
