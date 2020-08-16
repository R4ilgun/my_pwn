#! /usr/bin/python

import sys
import string
import base64
import hashlib
from pwn import *
from LibcSearcher import *

sl = lambda x:p.sendline(x)
sd = lambda x:p.send(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()

context.log_level = 'debug'

if(sys.argv[1] == 'l'):
	p = process("./")
	elf = ELF("./")
else:
	p = remote('39.107.202.142',31204)
	#elf = ELF("./")


'''
def getString2():

	hash_type = {
		"sha224":hashlib.sha224,
		"md5":hashlib.md5,
		"sha384":hashlib.sha384,
		"sha512":hashlib.sha512,
		"sha256":hashlib.sha256,
		"sha1":hashlib.sha1,
	}

	ru('x[:20] = ')
	hash_string = rv(20)

	ru('<built-in function openssl_')
	hash_way = ru('>')[:-1]

	success('hash:'+hash_string)
	success('type:'+hash_way)

	for i in string.printable:
		for j in string.printable:
			for k in string.printable:
				for l in string.printable:
					if(hash_type[hash_way](i+j+k+l).hexdigest()[:20] == hash_string):
						return (i+j+k+l)
					else:
						print ('no:' + (i+j+k+l))
'''

token = ''
	
ru('x[:20] = ')
hash_string = rv(20)

ru('<built-in function openssl_')
hash_way = ru('>')[:-1]
hash_way = 'hashlib.'+ hash_way
	

success('hash:'+hash_string)
success('type:'+hash_way)

get = False

for i in string.printable:
	if get:
		break
	for j in string.printable:
		if get:
			break
		for k in string.printable:
			if get:
				break
			for l in string.printable:
				if get:
					break
				if(eval(hash_way)(i+j+k+l).hexdigest()[:20] == hash_string):
					get = True


string = (i+j+k+l)
success(string)
ia()


ru("> Please input your token: ")
sl(token)

ru("...\n")
[p.recvline() for i in range(3)]

data = p.recvline()
f = open('binary.gz','w')
f.write(base64.b64decode(data))
f.close()

ia()