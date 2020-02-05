import hashlib

flag=''
flag+=chr(0x24^0x43)
flag+=chr(0x00^0x64)

print('backdoor:' + flag)
print('flag:PCTF{' +hashlib.sha256(flag).hexdigest() + '}')
