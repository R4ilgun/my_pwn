from pwn import *

context.log_level = 'debug'
p = process('./pwn-unupx')

p.sendline('7710642171487409988420420228601516803659013698495193403005751855185068351198')

p.interactive()