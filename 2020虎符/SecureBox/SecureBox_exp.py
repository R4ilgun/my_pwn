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
context.log_level='debug'

p = process("./SecureBox")
elf = ELF("./SecureBox")

def menu(cmd):
    sla("5.Exit\n",str(cmd))

def alloc(size):
    menu(1)
    sla("Size: ",str(size))

def delete(idx):
    menu(2)
    sla("Box ID: ",str(idx))

def enc(idx,offset,len,msg):
    menu(3)
    sla("Box ID: ",str(idx))
    sla("Offset of msg:",str(offset))
    sla("Len of msg: ",str(len))
    sla("Msg: ",msg)

def show(idx):
    menu(4)
    sla("Box ID: ",str(idx))
    sla("Offset of msg:",str(offset))
    sla("Len of msg: ",str(len))
    sla("Msg: ",msg)


alloc(0x110)
alloc(0x120)
delete(0)
alloc(0x110)

gdb.attach(p)

ia()